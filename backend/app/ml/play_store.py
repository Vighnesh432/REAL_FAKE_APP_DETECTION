"""
Play Store listing fetcher.

Turns a Play Store URL into the same AppInput shape the manual form produces, so a
scraped listing goes through the identical NLP + feature + classifier + rule pipeline
as hand-typed data. No separate code path to keep in sync.

WHY THIS MATTERS MORE THAN IT LOOKS: manual entry is the weakest link in the whole
tool — a user typing in the permissions a listing *claims* rather than what the
package actually declares. A Play Store link removes the typing entirely for the
description, reviews, ratings and (partially) permissions.

google_play_scraper hits Google's own backend endpoints directly (no HTML scraping,
no API key), so it is reasonably stable, but it is still an unofficial client for a
page Google could restructure at any time. Every call here is wrapped so a scraper
failure degrades to a clear error rather than a stack trace.
"""
import re
import time
from urllib.parse import parse_qs, urlparse

from google_play_scraper import Sort, app as gps_app, reviews as gps_reviews
from google_play_scraper import permissions as gps_permissions
from google_play_scraper.exceptions import NotFoundError

REQUEST_TIMEOUT = 12
REVIEW_SAMPLE = 15


class PlayStoreError(ValueError):
    pass


def is_play_store_url(url: str) -> bool:
    host = urlparse(url).netloc.lower()
    return host in ("play.google.com", "www.play.google.com")


def extract_app_id(url: str) -> str:
    parsed = urlparse(url)
    if "/store/apps/details" not in parsed.path:
        raise PlayStoreError(
            "That looks like a Play Store link, but not an app listing page. "
            "Use a link in the form play.google.com/store/apps/details?id=..."
        )
    app_id = parse_qs(parsed.query).get("id", [None])[0]
    if not app_id:
        raise PlayStoreError("No app id found in that Play Store link.")
    return app_id


# --------------------------------------------------------------------------- #
# Permission descriptions -> Android manifest constants
# --------------------------------------------------------------------------- #
# Play Store shows a human-readable phrase ("take pictures and videos"), not the
# manifest constant ("CAMERA"). The rule engine and feature extractor key off the
# constants, so this maps the common phrases across. Coverage is best-effort: an
# unmatched phrase still counts toward perm_count, it just won't be recognised as
# CATEGORY-dangerous or contribute to the SMS/accessibility/install-package checks.
PERMISSION_PHRASE_MAP = [
    (r"take pictures and videos", "CAMERA"),
    (r"record audio", "RECORD_AUDIO"),
    (r"read your contacts", "READ_CONTACTS"),
    (r"find accounts on the device", "GET_ACCOUNTS"),
    (r"read call log", "READ_CALL_LOG"),
    (r"read phone status and identity", "READ_PHONE_STATE"),
    (r"directly call phone numbers", "CALL_PHONE"),
    (r"read your text messages", "READ_SMS"),
    (r"send sms messages", "SEND_SMS"),
    (r"receive text messages", "RECEIVE_SMS"),
    (r"precise location", "ACCESS_FINE_LOCATION"),
    (r"approximate location", "ACCESS_COARSE_LOCATION"),
    (r"read the contents of your.*storage", "READ_EXTERNAL_STORAGE"),
    (r"modify or delete the contents of your.*storage", "WRITE_EXTERNAL_STORAGE"),
    (r"draw over other apps", "SYSTEM_ALERT_WINDOW"),
    (r"install other apps", "REQUEST_INSTALL_PACKAGES"),
    (r"have full access to accessibility features", "BIND_ACCESSIBILITY_SERVICE"),
    (r"run at startup", "RECEIVE_BOOT_COMPLETED"),
    (r"read calendar", "READ_CALENDAR"),
    (r"body sensors", "BODY_SENSORS"),
    (r"query all packages", "QUERY_ALL_PACKAGES"),
]
_COMPILED = [(re.compile(p), c) for p, c in PERMISSION_PHRASE_MAP]


def normalise_permissions(raw: dict) -> list[str]:
    """`raw` is google_play_scraper's permissions() return: {category: [phrases]}."""
    out = set()
    for phrases in (raw or {}).values():
        for phrase in phrases or []:
            phrase_l = str(phrase).lower()
            matched = next((const for rx, const in _COMPILED if rx.search(phrase_l)), None)
            out.add(matched or re.sub(r"[^A-Z0-9]+", "_", phrase.upper()).strip("_")[:40])
    out.add("INTERNET")   # virtually every listed app has network access
    return sorted(out)


# --------------------------------------------------------------------------- #
# Genre -> internal category
# --------------------------------------------------------------------------- #
GENRE_MAP = {
    "communication": "Communication", "social": "Communication",
    "photography": "Photography", "video players & editors": "Photography",
    "finance": "Finance", "business": "Finance",
    "productivity": "Productivity", "tools": "Productivity",
    "personalization": "Productivity", "libraries & demo": "Productivity",
    "health & fitness": "Health & Fitness", "medical": "Health & Fitness",
    "parenting": "Health & Fitness", "beauty": "Health & Fitness",
    "shopping": "Shopping", "food & drink": "Shopping",
    "education": "Education", "books & reference": "Education",
    "educational": "Education",
    "music & audio": "Music & Audio",
    "travel & local": "Travel", "maps & navigation": "Travel", "auto & vehicles": "Travel",
}
GAME_GENRE_RE = re.compile(r"^(action|adventure|arcade|board|card|casino|casual|"
                            r"educational|music|puzzle|racing|role playing|simulation|"
                            r"sports|strategy|trivia|word)$", re.I)


def map_genre(genre: str) -> str:
    g = str(genre or "").strip().lower()
    if g in GENRE_MAP:
        return GENRE_MAP[g]
    if GAME_GENRE_RE.match(g) or "game" in g:
        return "Games"
    return "Productivity"   # safe default; see module docstring on coverage limits


# --------------------------------------------------------------------------- #
# Field coercion helpers — Play Store's own fields are inconsistently typed
# --------------------------------------------------------------------------- #

def _parse_size_mb(size_field) -> float:
    s = str(size_field or "")
    m = re.match(r"([\d.]+)\s*([MG])", s, re.I)
    if not m:
        return 0.0
    val = float(m.group(1))
    return val * 1024 if m.group(1) and m.group(2).upper() == "G" else val


def _days_since(epoch_value) -> int:
    if not epoch_value:
        return 0
    ts = float(epoch_value)
    if ts > 10**12:      # milliseconds, not seconds
        ts /= 1000.0
    days = (time.time() - ts) / 86400.0
    return max(0, int(days))


# --------------------------------------------------------------------------- #
# Public entry point
# --------------------------------------------------------------------------- #

def fetch_app_input(url: str) -> dict:
    """Fetch a Play Store listing and return an AppInput-shaped dict."""
    app_id = extract_app_id(url)

    try:
        details = gps_app(app_id)
    except NotFoundError:
        raise PlayStoreError(f"No app found on the Play Store with id '{app_id}'.")
    except Exception as e:
        raise PlayStoreError(
            f"Could not reach the Play Store to fetch this listing ({type(e).__name__}). "
            "Try again, or enter the details manually."
        )

    try:
        perms_raw = gps_permissions(app_id)
        permissions = normalise_permissions(perms_raw)
    except Exception:
        permissions = ["INTERNET"]   # degrade rather than fail the whole scan

    try:
        review_list, _ = gps_reviews(app_id, sort=Sort.NEWEST, count=REVIEW_SAMPLE)
        reviews = [r.get("content", "") for r in review_list if r.get("content")]
    except Exception:
        reviews = []

    installs = int(details.get("realInstalls") or details.get("minInstalls") or 0)

    return {
        "app_name": details.get("title", app_id),
        "package_name": app_id,
        "category": map_genre(details.get("genre")),
        "description": details.get("description", "") or "",
        "reviews": reviews,
        "permissions": permissions,
        "rating": float(details.get("score") or 0.0),
        "rating_count": int(details.get("ratings") or 0),
        "installs": installs,
        "size_mb": _parse_size_mb(details.get("size")),
        "price": 0.0 if details.get("free", True) else 1.0,
        "days_since_update": _days_since(details.get("updated")),
        "app_age_days": 0,          # Play Store does not reliably expose first-publish date
        "developer_app_count": 0,   # would need an extra developer() call; omitted for latency
        "has_developer_website": 0,
        "has_privacy_policy": int(bool(details.get("privacyPolicy"))),
        "_source": {
            "developer": details.get("developer", ""),
            "store_url": details.get("url", url),
            "review_count_total": int(details.get("reviews") or 0),
        },
    }
