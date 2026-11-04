"""
Generic website trust check.

A Play Store listing has permissions, install counts and a review history to reason
about. A bare website has almost none of that, so running it through the app
classifier would produce a meaningless number dressed up as a probability. This
module is deliberately a *separate*, transparent rule engine rather than a forced fit
into the ML pipeline — every finding here is a named, inspectable check, not a learned
weight.

Scope, stated honestly: this catches the cheap, common tells (typosquatted domains,
credential-harvesting forms, TLS problems, spam-lexicon copy). It is not a replacement
for a maintained phishing-detection service such as Google Safe Browsing, and it has
no access to domain registration age, which is one of the strongest real signals and
would require a WHOIS lookup this module does not attempt.
"""
import re
from dataclasses import asdict
from difflib import SequenceMatcher
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

from .explain import Evidence, SEVERITY_WEIGHT, risk_band
from .preprocessing import SPAM_LEXICON, URGENCY_LEXICON, lexicon_ratio, tokenize

REQUEST_TIMEOUT = 10
MAX_BYTES = 3 * 1024 * 1024
USER_AGENT = "Mozilla/5.0 (compatible; AppXray-TrustCheck/1.0)"

# Brand -> official registrable domain. Deliberately the same trust idea as the APK
# package-identity check: a name match only matters when the domain doesn't back it up.
OFFICIAL_DOMAINS = {
    "whatsapp": "whatsapp.com", "instagram": "instagram.com", "telegram": "telegram.org",
    "phonepe": "phonepe.com", "paytm": "paytm.com", "google pay": "pay.google.com",
    "netflix": "netflix.com", "spotify": "spotify.com", "amazon": "amazon.com",
    "flipkart": "flipkart.com", "zoom": "zoom.us", "tiktok": "tiktok.com",
    "snapchat": "snapchat.com", "truecaller": "truecaller.com", "swiggy": "swiggy.com",
    "zomato": "zomato.com", "uber": "uber.com", "gmail": "gmail.com",
    "facebook": "facebook.com", "youtube": "youtube.com", "paypal": "paypal.com",
    "sbi": "sbi.co.in", "hdfc": "hdfcbank.com", "icici": "icicibank.com",
    "microsoft": "microsoft.com", "apple": "apple.com", "linkedin": "linkedin.com",
}
BRAND_NAMES = list(OFFICIAL_DOMAINS.keys())

SUSPICIOUS_TLDS = {"tk", "ml", "ga", "cf", "gq", "xyz", "top", "club", "work", "click",
                   "loan", "win", "review", "party", "download", "men", "date"}

CREDENTIAL_FIELD_RE = re.compile(
    r"password|passwd|pwd|otp|cvv|cvc|card.?number|pin\b|ssn|aadhaar|atm", re.I
)


class FetchError(ValueError):
    pass


_IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def _registrable_domain(host: str) -> str:
    """Naive eTLD+1 — good enough for the common two-and-three-label cases this
    check needs, without pulling in a public-suffix-list dependency."""
    if _IPV4_RE.match(host) or ":" in host:
        return host   # an IP address has no "registrable domain" — return as-is
    labels = host.lower().split(".")
    if len(labels) <= 2:
        return host.lower()
    two_part_tlds = {"co", "com", "org", "net", "gov", "ac", "edu"}
    if labels[-2] in two_part_tlds and len(labels[-1]) == 2:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _brand_domain_match(domain: str) -> tuple[float, str]:
    if _IPV4_RE.match(domain):
        return 0.0, ""
    base = domain.split(".")[0]
    best, brand = 0.0, ""
    for name in BRAND_NAMES:
        score = SequenceMatcher(None, base, name.replace(" ", "")).ratio()
        if score > best:
            best, brand = score, name
    return round(best, 4), brand


def _fetch(url: str) -> requests.Response:
    try:
        resp = requests.get(
            url, headers={"User-Agent": USER_AGENT}, timeout=REQUEST_TIMEOUT,
            allow_redirects=True, stream=True,
        )
    except requests.exceptions.SSLError as e:
        raise FetchError(f"TLS_ERROR::{e}")
    except requests.exceptions.RequestException as e:
        raise FetchError(f"Could not reach that site ({type(e).__name__}). "
                         "Check the URL and that the site is online.")

    content = resp.raw.read(MAX_BYTES, decode_content=True)
    resp._content = content
    return resp


def analyse_url(url: str) -> dict:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise FetchError("Enter a full URL starting with http:// or https://")

    host = parsed.netloc.lower().split(":")[0]
    domain = _registrable_domain(host)
    tld = domain.rsplit(".", 1)[-1]

    tls_error = None
    try:
        resp = _fetch(url)
    except FetchError as e:
        if str(e).startswith("TLS_ERROR::"):
            tls_error = str(e).split("::", 1)[1]
            resp = _fetch(url.replace("https://", "http://", 1)) if url.startswith("https://") else None
            if resp is None:
                raise FetchError(
                    "This site's TLS certificate is invalid or self-signed, and the page "
                    "could not be loaded at all. Treat it as unsafe."
                )
        else:
            raise

    final_host = urlparse(resp.url).netloc.lower().split(":")[0]
    redirected_offsite = final_host and _registrable_domain(final_host) != domain
    redirect_count = len(resp.history)

    soup = BeautifulSoup(resp.content, "html.parser")
    title = (soup.title.string or "").strip() if soup.title and soup.title.string else ""
    meta_desc_tag = soup.find("meta", attrs={"name": "description"})
    meta_desc = meta_desc_tag.get("content", "").strip() if meta_desc_tag else ""

    for tag in soup(["script", "style", "noscript"]):
        tag.decompose()
    visible_text = " ".join(soup.get_text(" ").split())[:20000]
    tokens = tokenize(visible_text)

    credential_forms = []
    for form in soup.find_all("form"):
        action = form.get("action", "") or ""
        action_url = urljoin(resp.url, action)
        action_host = urlparse(action_url).netloc.lower().split(":")[0]
        asks_credentials = bool(form.find(
            lambda t: t.name == "input" and CREDENTIAL_FIELD_RE.search(
                " ".join(str(t.get(a, "")) for a in ("name", "id", "placeholder", "type"))
            )
        ))
        offsite_action = bool(action_host) and _registrable_domain(action_host) != domain
        if asks_credentials:
            credential_forms.append({"offsite": offsite_action, "action_host": action_host})

    brand_sim, brand = _brand_domain_match(domain)
    is_official = domain == OFFICIAL_DOMAINS.get(brand, "__none__")

    # ---------------------------------------------------------------- evidence
    evidence: list[Evidence] = []

    if brand_sim >= 0.82 and not is_official:
        evidence.append(Evidence(
            "Impersonates a known brand domain",
            f"'{domain}' closely resembles {brand.title()} ({brand_sim:.0%} similarity) "
            f"but is not {brand.title()}'s official domain ({OFFICIAL_DOMAINS.get(brand)}).",
            "critical", "risk", brand_sim))
    elif is_official:
        evidence.append(Evidence(
            "Matches official brand domain",
            f"'{domain}' is {brand.title()}'s registered official domain.",
            "high", "trust", 1.0))

    if tld in SUSPICIOUS_TLDS:
        evidence.append(Evidence(
            "Uncommon top-level domain",
            f"'.{tld}' is a low-cost TLD frequently used for disposable phishing "
            "domains. Not proof of fraud on its own, but rarely used by established brands.",
            "medium", "risk", 1.0))

    if _IPV4_RE.match(domain):
        evidence.append(Evidence(
            "Raw IP address instead of a domain",
            "The link points directly at an IP address rather than a registered domain "
            "name. Legitimate consumer-facing services do not normally ask users to "
            "visit a bare IP address.",
            "high", "risk", 1.0))

    if tls_error:
        evidence.append(Evidence(
            "Invalid TLS certificate",
            f"The site's certificate failed validation ({tls_error.splitlines()[0][:120]}). "
            "A legitimate service protecting user data will not normally present a broken certificate.",
            "critical", "risk", 1.0))
    elif url.startswith("http://"):
        evidence.append(Evidence(
            "No encryption (plain HTTP)",
            "The page was served without TLS, so any data submitted is not encrypted in transit.",
            "high", "risk", 1.0))
    else:
        evidence.append(Evidence(
            "Valid HTTPS connection",
            "The page was served over a validated TLS connection.",
            "low", "trust", 1.0))

    if redirected_offsite:
        evidence.append(Evidence(
            "Redirects to a different domain",
            f"The link redirected to '{final_host}', a different domain than the one entered.",
            "high", "risk", 1.0))
    elif redirect_count >= 3:
        evidence.append(Evidence(
            "Long redirect chain",
            f"The page went through {redirect_count} redirects before loading.",
            "low", "risk", float(redirect_count)))

    offsite_cred_forms = [f for f in credential_forms if f["offsite"]]
    if offsite_cred_forms:
        evidence.append(Evidence(
            "Credential form submits off-domain",
            f"A form requesting a password, OTP or card number sends its data to "
            f"'{offsite_cred_forms[0]['action_host']}', not to '{domain}' itself. "
            "This is the single strongest sign of a credential-harvesting page.",
            "critical", "risk", 1.0))
    elif credential_forms:
        evidence.append(Evidence(
            "Requests sensitive credentials",
            "The page contains a form asking for a password, OTP, PIN or card number. "
            "Verify the domain independently before entering anything.",
            "medium", "risk", float(len(credential_forms))))

    spam_ratio = lexicon_ratio(tokens, SPAM_LEXICON)
    urgency_ratio = lexicon_ratio(tokens, URGENCY_LEXICON)
    if spam_ratio >= 0.12:
        evidence.append(Evidence(
            "Promotional, keyword-stuffed copy",
            f"{spam_ratio:.0%} of the page's words are promotional filler "
            "('free', 'guaranteed', 'unlimited').",
            "medium", "risk", spam_ratio))
    if urgency_ratio >= 0.05:
        evidence.append(Evidence(
            "Urgency language",
            "The page repeatedly uses pressure phrases ('now', 'hurry', 'limited', 'immediately'), "
            "a common tactic to short-circuit careful reading.",
            "medium", "risk", urgency_ratio))

    if not title and not meta_desc:
        evidence.append(Evidence(
            "No page title or description",
            "The page has neither a title nor a meta description, unusual for a "
            "legitimate, maintained site.",
            "low", "risk", 0.0))

    risk_w = sum(SEVERITY_WEIGHT[e.severity] for e in evidence if e.direction == "risk")
    trust_w = sum(SEVERITY_WEIGHT[e.severity] for e in evidence if e.direction == "trust")
    score = round(max(0.0, min(1.0, (risk_w - 0.8 * trust_w) / 12.0)) * 100, 1)
    band = risk_band(score / 100)

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    top = sorted([e for e in evidence if e.direction == "risk"], key=lambda e: order[e.severity])[:6]

    if band in ("Critical", "High"):
        recommendation = "Do not enter any personal information on this site."
    elif band == "Moderate":
        recommendation = "Verify this domain independently before entering any information."
    else:
        recommendation = "No strong indicators of a fraudulent site were found."

    grouped: dict[str, list] = {}
    for e in evidence:
        grouped.setdefault("website", []).append(asdict(e))

    return {
        "verdict": "Fake" if score >= 50 else "Genuine",
        "fake_probability": round(score / 100, 4),
        "confidence": round(abs(score / 100 - 0.5) * 2, 4),
        "risk_score": score,
        "risk_band": band,
        "model_used": "website_heuristics",
        "model_alignment": 1.0,
        "recommendation": recommendation,
        "evidence": {
            "grouped": grouped,
            "rule_risk_score": score,
            "risk_signal_count": sum(1 for e in evidence if e.direction == "risk"),
            "trust_signal_count": sum(1 for e in evidence if e.direction == "trust"),
            "top_reasons": [asdict(e) for e in top],
        },
        "features": {},
        "app": {
            "app_name": title or domain,
            "package_name": domain,
            "category": "Website",
        },
    }
