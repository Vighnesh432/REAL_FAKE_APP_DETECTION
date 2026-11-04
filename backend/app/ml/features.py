import math
import re
from difflib import SequenceMatcher

import numpy as np
import pandas as pd

from .preprocessing import (
    NEGATIVE_LEXICON, SPAM_LEXICON, URGENCY_LEXICON,
    lexicon_ratio, sentiment_score, split_reviews, tokenize,
)

POPULAR_BRANDS = [
    "whatsapp", "instagram", "telegram", "phonepe", "paytm", "google pay",
    "netflix", "spotify", "amazon", "flipkart", "zoom", "tiktok", "snapchat",
    "pubg mobile", "free fire", "truecaller", "swiggy", "zomato", "uber", "gmail",
    "facebook", "youtube", "sbi", "hdfc", "icici", "aadhaar", "paypal",
]

# The official package identifier for each impersonated brand. A brand-name match is
# only evidence of impersonation when the package does NOT match the official one —
# the genuine WhatsApp scores 1.0 similarity against "whatsapp" too, so name
# similarity alone cannot distinguish it from a counterfeit.
OFFICIAL_PACKAGES = {
    "whatsapp": {"com.whatsapp", "com.whatsapp.w4b"},
    "instagram": {"com.instagram.android"},
    "telegram": {"org.telegram.messenger", "org.thunderdog.challegram"},
    "phonepe": {"com.phonepe.app"},
    "paytm": {"net.one97.paytm"},
    "google pay": {"com.google.android.apps.nbu.paisa.user",
                   "com.google.android.apps.walletnfcrel"},
    "netflix": {"com.netflix.mediaclient"},
    "spotify": {"com.spotify.music"},
    "amazon": {"com.amazon.mShop.android.shopping"},
    "flipkart": {"com.flipkart.android"},
    "zoom": {"us.zoom.videomeetings"},
    "tiktok": {"com.zhiliaoapp.musically", "com.ss.android.ugc.trill"},
    "snapchat": {"com.snapchat.android"},
    "pubg mobile": {"com.tencent.ig", "com.pubg.imobile"},
    "free fire": {"com.dts.freefireth", "com.dts.freefiremax"},
    "truecaller": {"com.truecaller"},
    "swiggy": {"in.swiggy.android"},
    "zomato": {"com.application.zomato"},
    "uber": {"com.ubercab"},
    "gmail": {"com.google.android.gm"},
    "facebook": {"com.facebook.katana", "com.facebook.lite"},
    "youtube": {"com.google.android.youtube"},
    "paypal": {"com.paypal.android.p2pmobile"},
}
ALL_OFFICIAL = {pkg for pkgs in OFFICIAL_PACKAGES.values() for pkg in pkgs}

DANGEROUS_PERMISSIONS = {
    "READ_SMS", "SEND_SMS", "RECEIVE_SMS", "READ_CALL_LOG", "WRITE_CALL_LOG",
    "CALL_PHONE", "READ_CONTACTS", "WRITE_CONTACTS", "ACCESS_FINE_LOCATION",
    "ACCESS_BACKGROUND_LOCATION", "RECORD_AUDIO", "CAMERA", "READ_EXTERNAL_STORAGE",
    "WRITE_EXTERNAL_STORAGE", "GET_ACCOUNTS", "SYSTEM_ALERT_WINDOW",
    "REQUEST_INSTALL_PACKAGES", "QUERY_ALL_PACKAGES", "READ_PHONE_STATE",
    "BIND_ACCESSIBILITY_SERVICE", "READ_CALENDAR", "BODY_SENSORS",
}

CATEGORY_EXPECTED = {
    "Communication": {"INTERNET", "READ_CONTACTS", "RECORD_AUDIO", "CAMERA", "VIBRATE",
                      "POST_NOTIFICATIONS", "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE"},
    "Photography": {"INTERNET", "CAMERA", "READ_MEDIA_IMAGES", "WRITE_EXTERNAL_STORAGE",
                    "READ_EXTERNAL_STORAGE"},
    "Finance": {"INTERNET", "USE_BIOMETRIC", "POST_NOTIFICATIONS", "CAMERA", "READ_PHONE_STATE"},
    "Games": {"INTERNET", "VIBRATE", "WAKE_LOCK", "BILLING", "WRITE_EXTERNAL_STORAGE"},
    "Productivity": {"INTERNET", "READ_MEDIA_IMAGES", "POST_NOTIFICATIONS",
                     "WRITE_EXTERNAL_STORAGE", "READ_EXTERNAL_STORAGE", "READ_CALENDAR"},
    "Health & Fitness": {"INTERNET", "ACTIVITY_RECOGNITION", "BODY_SENSORS",
                         "ACCESS_FINE_LOCATION", "POST_NOTIFICATIONS"},
    "Shopping": {"INTERNET", "POST_NOTIFICATIONS", "ACCESS_COARSE_LOCATION", "CAMERA"},
    "Education": {"INTERNET", "WRITE_EXTERNAL_STORAGE", "POST_NOTIFICATIONS",
                  "READ_EXTERNAL_STORAGE"},
    "Music & Audio": {"INTERNET", "WAKE_LOCK", "READ_MEDIA_AUDIO", "BLUETOOTH",
                      "POST_NOTIFICATIONS"},
    "Travel": {"INTERNET", "ACCESS_FINE_LOCATION", "CAMERA", "POST_NOTIFICATIONS"},
}
CATEGORIES = list(CATEGORY_EXPECTED.keys())

STRUCTURED_FEATURES = [
    "name_brand_similarity", "name_has_fake_suffix", "name_has_leetspeak", "name_length",
    "package_depth_anomaly",
    "desc_length", "desc_word_count", "desc_unique_ratio", "desc_spam_ratio",
    "desc_urgency_ratio", "desc_exclaim_density", "desc_caps_ratio", "desc_digit_ratio",
    "review_count_sampled", "review_avg_length", "review_duplicate_ratio",
    "review_unique_ratio", "review_sentiment_mean", "review_sentiment_std",
    "review_negative_ratio",
    "perm_count", "perm_dangerous_count", "perm_dangerous_ratio", "perm_mismatch_count",
    "perm_mismatch_ratio", "has_sms_permission", "has_accessibility_permission",
    "has_install_packages_permission",
    "rating", "rating_count_log", "installs_log", "ratings_per_install",
    "rating_deviation", "size_mb", "size_per_install_log", "days_since_update",
    "app_age_days_log", "developer_app_count", "has_developer_website",
    "has_privacy_policy", "is_free",
]


def _best_brand_match(name: str) -> tuple[float, str]:
    n = re.sub(r"[^a-z0-9 ]", "", str(name).lower()).strip()
    if not n:
        return 0.0, ""
    best, best_brand = 0.0, ""
    for brand in POPULAR_BRANDS:
        score = SequenceMatcher(None, n, brand).ratio()
        score = max(score, SequenceMatcher(None, n.split()[0], brand.split()[0]).ratio())
        if score > best:
            best, best_brand = score, brand
    return round(best, 4), best_brand


def _brand_similarity(name: str) -> float:
    return _best_brand_match(name)[0]


def is_official_app(name: str, package: str) -> bool:
    pkg = str(package).strip()
    if not pkg:
        return False
    if pkg in ALL_OFFICIAL:
        return True
    sim, brand = _best_brand_match(name)
    return sim >= 0.82 and pkg in OFFICIAL_PACKAGES.get(brand, set())


def _has_leetspeak(name: str) -> int:
    return int(bool(re.search(r"[a-zA-Z][0-9@$!|]{1}[a-zA-Z]", str(name))))


FAKE_SUFFIX_RE = re.compile(
    r"\b(mod|apk|cracked|unlocked|premium|vip|gold|plus|pro|free|latest|"
    r"official|new version|20\d\d)\b", re.I
)
# Reverse-DNS with a recognised leading segment and 2-6 parts total.
PACKAGE_OK_RE = re.compile(
    r"^(com|org|net|io|in|co|me|app|dev|edu|gov|us|uk|de|fr|jp|cn|ru|br)"
    r"(\.[a-zA-Z][a-zA-Z0-9_]*){1,5}$"
)


def _safe_log(x, base=10.0):
    return float(math.log(max(float(x), 0.0) + 1.0, base))


def extract_structured(row: dict) -> dict:
    name = str(row.get("app_name", ""))
    pkg = str(row.get("package_name", ""))
    desc = str(row.get("description", ""))
    category = row.get("category", "Productivity")
    reviews = split_reviews(row.get("reviews", ""))

    perms = {p.strip().upper() for p in str(row.get("permissions", "")).split(";") if p.strip()}
    expected = CATEGORY_EXPECTED.get(category, set())
    dangerous = perms & DANGEROUS_PERMISSIONS
    mismatch = dangerous - expected

    desc_tokens = tokenize(desc)
    desc_words = desc.split()
    n_words = max(len(desc_words), 1)

    review_tokens_lens = [len(r.split()) for r in reviews]
    review_sents = [sentiment_score(r) for r in reviews] or [0.0]
    norm_reviews = [re.sub(r"\W+", " ", r.lower()).strip() for r in reviews]
    n_rev = max(len(reviews), 1)

    installs = float(row.get("installs", 0) or 0)
    rating_count = float(row.get("rating_count", 0) or 0)
    size_mb = float(row.get("size_mb", 0) or 0)

    f = {
        "name_brand_similarity": _brand_similarity(name),
        "name_has_fake_suffix": int(bool(FAKE_SUFFIX_RE.search(name))),
        "name_has_leetspeak": _has_leetspeak(name),
        "name_length": len(name),
        "package_depth_anomaly": int(not PACKAGE_OK_RE.match(pkg) if pkg else 0),

        "desc_length": len(desc),
        "desc_word_count": len(desc_words),
        "desc_unique_ratio": len(set(desc_tokens)) / max(len(desc_tokens), 1),
        "desc_spam_ratio": lexicon_ratio(desc_tokens, SPAM_LEXICON),
        "desc_urgency_ratio": lexicon_ratio(desc_tokens, URGENCY_LEXICON),
        "desc_exclaim_density": desc.count("!") / n_words,
        "desc_caps_ratio": sum(c.isupper() for c in desc) / max(len(desc), 1),
        "desc_digit_ratio": sum(c.isdigit() for c in desc) / max(len(desc), 1),

        "review_count_sampled": len(reviews),
        "review_avg_length": float(np.mean(review_tokens_lens)) if review_tokens_lens else 0.0,
        "review_duplicate_ratio": 1.0 - (len(set(norm_reviews)) / n_rev),
        "review_unique_ratio": len(set(norm_reviews)) / n_rev,
        "review_sentiment_mean": float(np.mean(review_sents)),
        "review_sentiment_std": float(np.std(review_sents)),
        "review_negative_ratio": sum(
            1 for r in reviews if any(w in r.lower() for w in NEGATIVE_LEXICON)
        ) / n_rev,

        "perm_count": len(perms),
        "perm_dangerous_count": len(dangerous),
        "perm_dangerous_ratio": len(dangerous) / max(len(perms), 1),
        "perm_mismatch_count": len(mismatch),
        "perm_mismatch_ratio": len(mismatch) / max(len(perms), 1),
        "has_sms_permission": int(bool(perms & {"READ_SMS", "SEND_SMS", "RECEIVE_SMS"})),
        "has_accessibility_permission": int("BIND_ACCESSIBILITY_SERVICE" in perms),
        "has_install_packages_permission": int("REQUEST_INSTALL_PACKAGES" in perms),

        "rating": float(row.get("rating", 0) or 0),
        "rating_count_log": _safe_log(rating_count),
        "installs_log": _safe_log(installs),
        "ratings_per_install": rating_count / max(installs, 1.0),
        "rating_deviation": abs(float(row.get("rating", 4.2) or 4.2) - 4.2),
        "size_mb": size_mb,
        "size_per_install_log": _safe_log(size_mb / max(installs, 1.0) * 1e6),
        "days_since_update": float(row.get("days_since_update", 0) or 0),
        "app_age_days_log": _safe_log(row.get("app_age_days", 0) or 0),
        "developer_app_count": float(row.get("developer_app_count", 0) or 0),
        "has_developer_website": int(row.get("has_developer_website", 0) or 0),
        "has_privacy_policy": int(row.get("has_privacy_policy", 0) or 0),
        "is_free": int(float(row.get("price", 0) or 0) == 0.0),
    }
    return {k: float(f[k]) for k in STRUCTURED_FEATURES}


def build_structured_matrix(df: pd.DataFrame) -> pd.DataFrame:
    rows = [extract_structured(r) for r in df.to_dict("records")]
    return pd.DataFrame(rows, columns=STRUCTURED_FEATURES).astype(np.float32)


def build_text_corpus(df: pd.DataFrame) -> tuple[list[str], list[str]]:
    from .preprocessing import preprocess
    desc = [preprocess(t) for t in df["description"].fillna("").astype(str)]
    revs = [preprocess(t.replace("||", " ")) for t in df["reviews"].fillna("").astype(str)]
    return desc, revs


def build_category_matrix(df: pd.DataFrame) -> pd.DataFrame:
    cats = df["category"].fillna("Productivity").astype(str)
    mat = pd.DataFrame({f"cat_{c}": (cats == c).astype(np.float32) for c in CATEGORIES})
    return mat
