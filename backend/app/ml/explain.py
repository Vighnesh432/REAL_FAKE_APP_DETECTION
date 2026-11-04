from dataclasses import asdict, dataclass

SEVERITY_WEIGHT = {"critical": 4.0, "high": 3.0, "medium": 2.0, "low": 1.0}


@dataclass
class Evidence:
    signal: str
    detail: str
    severity: str
    direction: str
    value: float


def _identity_rules_from_certificate(verdict: str, package: str, meta: dict) -> list[Evidence]:
    """Only reached when an APK binary was actually analysed AND its package name is
    literally a tracked brand's official identifier -- see identity.py. Cryptographic
    proof (or its absence) always takes priority over metadata inference here."""
    brand = meta.get("identity_claimed_brand") or "a known publisher"

    if verdict == "certificate_mismatch":
        return [Evidence(
            "Signing certificate does not match the known publisher",
            f"This file's package identifier ('{package}') belongs to {brand}, but the "
            f"certificate that actually signed this file does not match the certificate "
            f"on record for {brand}. A repackager can copy a package name into the "
            "manifest verbatim; they cannot copy the original signing key. This is "
            "direct evidence of a modified, resigned, or counterfeit build -- regardless "
            "of how clean its permissions, description or rating look.",
            "critical", "risk", 1.0)]

    if verdict == "verified_official":
        return [Evidence(
            "Verified publisher signature",
            f"'{package}' is signed with the certificate on file for {brand}. Unlike a "
            "package name, a signing certificate cannot be reproduced without the "
            "original private key, so this is cryptographic proof, not an inference "
            "from copyable metadata.",
            "high", "trust", 1.0)]

    if verdict == "unverifiable_no_certificate":
        return [Evidence(
            "Official package name, no verifiable signature",
            f"The package '{package}' matches {brand}, but no signing certificate could "
            "be read from this file at all. A validly built, installable APK always "
            "carries one, so this file is treated as unverified rather than trusted.",
            "high", "risk", 1.0)]

    if verdict == "unverified_no_pin":
        return [Evidence(
            "Official package name, signature not yet verifiable",
            f"The package '{package}' matches {brand}, but this deployment has no "
            f"reference certificate on file for {brand} yet, so there is nothing to "
            "compare against. Neither trusted nor penalised for that reason alone -- "
            "scored like any third-party app until an administrator pins a verified "
            "certificate (see backend/scripts/pin_signer.py).",
            "low", "info", 0.0)]

    return []  # third_party: nothing brand-specific to say


def _identity_rules(f: dict, meta: dict) -> list[Evidence]:
    from .features import is_official_app

    out = []
    sim = f["name_brand_similarity"]
    name = meta.get("app_name", "")
    package = meta.get("package_name", "")
    verdict = meta.get("identity_verdict")  # set only when an APK binary was analysed

    if verdict in ("verified_official", "certificate_mismatch",
                   "unverifiable_no_certificate", "unverified_no_pin"):
        # An APK was analysed and its package name is a tracked brand's OFFICIAL
        # identifier, so a certificate check is meaningful -- it takes priority over
        # the name-similarity heuristic below.
        return _identity_rules_from_certificate(verdict, package, meta) + _identity_secondary(f, meta)

    if verdict is None and is_official_app(name, package):
        # No APK binary was analysed (Play Store listing or manual entry). There is no
        # file to extract a certificate from, but the Store's own namespace uniqueness
        # is a real gatekeeping mechanism here -- a package-name match on a live
        # listing means Google's own registry vouches for that listing's publisher.
        # This says nothing about any APK obtained outside the Store.
        out.append(Evidence(
            "Official package name on Play Store",
            f"'{package}' is the package identifier Google Play associates with this "
            "listing. Play Store enforces package-name uniqueness, so a counterfeit "
            "cannot publish a listing under it.",
            "high", "trust", 1.0))
        return out + _identity_secondary(f, meta)

    # Reached when: an APK was analysed but its package doesn't match any tracked
    # brand (identity_verdict == "third_party"), or no APK was analysed and the
    # package didn't match on a listing either. Either way, fall back to plain
    # name-similarity impersonation detection.
    if sim >= 0.82:
        out.append(Evidence(
            "Impersonates a known app",
            f"The name closely resembles a widely-used app (similarity {sim:.0%}), but "
            f"the package '{package or 'not provided'}' is not that app's official "
            "identifier. Counterfeits rely on users mistaking them for the original.",
            "critical", "risk", sim))
    elif sim >= 0.65:
        out.append(Evidence(
            "Name resembles a known brand",
            f"Partial resemblance to a popular app name ({sim:.0%}). May be coincidental.",
            "medium", "risk", sim))

    return out + _identity_secondary(f, meta)


def _identity_secondary(f: dict, meta: dict) -> list[Evidence]:
    out = []
    if f["name_has_leetspeak"]:
        out.append(Evidence(
            "Character substitution in name",
            "Digits or symbols replace letters (e.g. 'Netfl1x'). This is a standard "
            "technique for evading store name filters.",
            "high", "risk", 1.0))

    if f["name_has_fake_suffix"]:
        out.append(Evidence(
            "Modified-build wording in name",
            "The name contains terms like Mod, Cracked, APK or Unlocked, associated with "
            "repackaged builds distributed outside official channels.",
            "medium", "risk", 1.0))

    if f["package_depth_anomaly"] and meta.get("package_name"):
        out.append(Evidence(
            "Non-standard package identifier",
            f"Package '{meta.get('package_name', '')}' does not parse as a valid "
            "reverse-domain identifier.",
            "medium", "risk", 1.0))
    return out


def _permission_rules(f: dict, meta: dict) -> list[Evidence]:
    out = []
    if f["has_sms_permission"]:
        out.append(Evidence(
            "Requests SMS access",
            "SMS permissions allow an app to read one-time passcodes. Very few app "
            "categories have a legitimate reason to request this.",
            "critical", "risk", 1.0))

    if f["has_accessibility_permission"]:
        out.append(Evidence(
            "Requests Accessibility Service",
            "Accessibility APIs can read screen contents and simulate taps. Widely abused "
            "by banking trojans to perform actions on the user's behalf.",
            "critical", "risk", 1.0))

    if f["has_install_packages_permission"]:
        out.append(Evidence(
            "Can install other packages",
            "The app can install additional software, allowing a payload to be delivered "
            "after the initial store review.",
            "high", "risk", 1.0))

    mm = int(f["perm_mismatch_count"])
    if mm >= 5:
        out.append(Evidence(
            "Permissions unrelated to purpose",
            f"{mm} sensitive permissions have no plausible use for a "
            f"{meta.get('category', 'this')} app. Over-requesting is the strongest static "
            "indicator of a repackaged application.",
            "critical", "risk", float(mm)))
    elif mm >= 2:
        out.append(Evidence(
            "Some permissions look excessive",
            f"{mm} sensitive permissions are not typical for this category.",
            "medium", "risk", float(mm)))
    elif f["perm_count"] <= 6 and mm == 0:
        out.append(Evidence(
            "Permission set matches purpose",
            f"All {int(f['perm_count'])} requested permissions are consistent with a "
            f"{meta.get('category', 'this')} app.",
            "medium", "trust", f["perm_count"]))
    return out


def _text_rules(f: dict, meta: dict) -> list[Evidence]:
    out = []

    # Upload-APK's description field is optional -- leaving it blank is completely
    # normal when scanning a binary, not "thin content". Without this guard, EVERY
    # APK upload with no typed description was penalised as if a publisher had
    # written a suspiciously short listing, which is a fabricated signal, not a real
    # one. Same "absence isn't evidence" principle as the marketplace guard below.
    if f["desc_word_count"] == 0:
        out.append(Evidence(
            "No description provided",
            "No app description was entered for this scan -- normal for a directly "
            "uploaded APK file. Description-based signals are skipped rather than "
            "scored as suspicious for the absence of text.",
            "low", "risk", 0.0))
        return out

    if f["desc_spam_ratio"] >= 0.28:
        out.append(Evidence(
            "Keyword-stuffed description",
            f"{f['desc_spam_ratio']:.0%} of description words are promotional filler "
            "('free', 'unlimited', 'guaranteed'). Written for store search ranking, not users.",
            "high", "risk", f["desc_spam_ratio"]))
    elif f["desc_spam_ratio"] >= 0.15:
        out.append(Evidence(
            "Heavily promotional description",
            f"Elevated promotional wording ({f['desc_spam_ratio']:.0%} of words).",
            "low", "risk", f["desc_spam_ratio"]))

    if f["desc_exclaim_density"] >= 0.08:
        out.append(Evidence(
            "Excessive urgency punctuation",
            "Dense use of exclamation marks, a common pressure tactic in fraudulent listings.",
            "medium", "risk", f["desc_exclaim_density"]))

    if f["desc_word_count"] < 25:
        out.append(Evidence(
            "Thin description",
            f"Only {int(f['desc_word_count'])} words. Established publishers document "
            "features, permissions and privacy practices in detail.",
            "medium", "risk", f["desc_word_count"]))

    if f["desc_unique_ratio"] < 0.55 and f["desc_word_count"] >= 15:
        out.append(Evidence(
            "Repetitive wording",
            f"Only {f['desc_unique_ratio']:.0%} of terms are distinct — the text repeats "
            "itself, typical of machine-generated listing copy.",
            "medium", "risk", f["desc_unique_ratio"]))
    return out


def _review_rules(f: dict, meta: dict) -> list[Evidence]:
    out = []
    if f["review_duplicate_ratio"] >= 0.5 and f["review_count_sampled"] >= 4:
        out.append(Evidence(
            "Duplicated review text",
            f"{f['review_duplicate_ratio']:.0%} of sampled reviews repeat the same wording. "
            "Organic reviews rarely duplicate; review farms reuse a small set of phrases.",
            "high", "risk", f["review_duplicate_ratio"]))

    if f["review_avg_length"] < 5 and f["review_count_sampled"] >= 4:
        out.append(Evidence(
            "Reviews lack specificity",
            f"Reviews average {f['review_avg_length']:.1f} words and mention no concrete "
            "features. Incentivised reviews are short and generic.",
            "medium", "risk", f["review_avg_length"]))

    if f["review_sentiment_std"] < 0.08 and f["review_sentiment_mean"] > 0.6:
        out.append(Evidence(
            "Uniformly positive reviews",
            "Sentiment shows almost no variance. Real user bases disagree; a perfectly "
            "consistent one suggests coordinated posting.",
            "high", "risk", f["review_sentiment_std"]))

    if f["review_negative_ratio"] >= 0.4:
        out.append(Evidence(
            "Users report fraud",
            f"{f['review_negative_ratio']:.0%} of sampled reviews contain fraud-related "
            "complaints (scam, stolen OTP, unauthorised charges).",
            "critical", "risk", f["review_negative_ratio"]))

    if (f["review_sentiment_std"] > 0.35 and f["review_avg_length"] > 10
            and f["review_duplicate_ratio"] < 0.2):
        out.append(Evidence(
            "Reviews look organic",
            "Detailed reviews with mixed sentiment and no duplication — the pattern of a "
            "genuine user base.",
            "medium", "trust", f["review_sentiment_std"]))
    return out


def _marketplace_rules(f: dict, meta: dict) -> list[Evidence]:
    out = []

    # A raw APK upload has no Play Store listing behind it -- rating/installs/age are
    # never fetched for it (see routers/predict.py, predict_from_apk), so they sit at
    # their default of exactly 0. Without this guard, "0 installs, 0 rating, age 0"
    # reads as "brand-new app with a suspicious rating history" and manufactures
    # several risk signals purely out of an absence of data -- which previously made
    # a directly-uploaded, completely genuine APK look worse than the same app
    # scanned via its Play Store link. Absence of marketplace data is reported once,
    # plainly, instead of being scored as if it were evidence of anything.
    no_listing_data = (
        f["installs_log"] == 0.0 and f["rating"] == 0.0 and f["rating_count_log"] == 0.0
    )
    if no_listing_data:
        out.append(Evidence(
            "No marketplace listing data",
            "This scan has no Play Store rating, install count, or listing age to "
            "check -- typical for a directly-uploaded APK file rather than a Play "
            "Store link. Marketplace-based signals are skipped rather than scored as "
            "suspicious for the absence of data.",
            "low", "risk", 0.0))
        return out

    rpi = f["ratings_per_install"]
    if rpi > 0.12:
        out.append(Evidence(
            "Implausible rating volume",
            f"Roughly one rating per {max(int(1 / max(rpi, 1e-6)), 1)} installs. Healthy "
            "apps convert 0.25-2% of installs into ratings; this is far above that.",
            "critical", "risk", rpi))
    elif rpi > 0.05:
        out.append(Evidence(
            "Elevated rating-to-install ratio",
            "More ratings per install than typical, which can indicate purchased ratings.",
            "medium", "risk", rpi))

    if f["rating"] >= 4.75 and f["rating_count_log"] < 3.0:
        out.append(Evidence(
            "Near-perfect rating, few raters",
            f"A {f['rating']:.1f} average from a small rater pool is easy to manufacture "
            "and easy to fake.",
            "medium", "risk", f["rating"]))

    # play_store.py does not fetch first-publish date or developer app count (an extra
    # API call per scan for latency reasons) -- both are hardcoded to 0 for EVERY live
    # scrape, real or fake. Treating that placeholder as "brand new, no track record"
    # made every Play-Store-scanned app look suspicious on these two signals
    # regardless of the actual publisher's age or history. Only apply them when a
    # real, non-default value is actually present.
    publisher_history_unknown = f["app_age_days_log"] == 0.0
    if not publisher_history_unknown and f["app_age_days_log"] < 2.2:
        out.append(Evidence(
            "Recently published",
            "The listing is new. Counterfeits are published, harvested, and taken down "
            "within weeks, so age is a meaningful trust signal.",
            "medium", "risk", f["app_age_days_log"]))

    if (not publisher_history_unknown and f["developer_app_count"] <= 1
            and not f["has_developer_website"]):
        out.append(Evidence(
            "Publisher has no track record",
            "One published app, no developer website. Consistent with a throwaway "
            "account — though also common for genuine independent developers.",
            "low", "risk", f["developer_app_count"]))

    if not f["has_privacy_policy"]:
        out.append(Evidence(
            "No privacy policy",
            "No privacy policy is linked, despite the app requesting sensitive permissions.",
            "high" if f["perm_dangerous_count"] >= 5 else "medium", "risk", 0.0))

    if f["developer_app_count"] >= 8 and f["has_developer_website"] and f["has_privacy_policy"]:
        out.append(Evidence(
            "Established publisher",
            f"{int(f['developer_app_count'])} published apps with a developer website and "
            "privacy policy — an account with something to lose.",
            "medium", "trust", f["developer_app_count"]))

    if f["days_since_update"] > 540:
        out.append(Evidence(
            "Abandoned listing",
            f"No update in {int(f['days_since_update'])} days. Unmaintained apps accumulate "
            "unpatched vulnerabilities even when originally legitimate.",
            "low", "risk", f["days_since_update"]))
    return out


RULE_GROUPS = [
    ("identity", _identity_rules),
    ("permissions", _permission_rules),
    ("description", _text_rules),
    ("reviews", _review_rules),
    ("marketplace", _marketplace_rules),
]


def build_evidence(features: dict, meta: dict) -> dict:
    grouped, flat = {}, []
    for group, fn in RULE_GROUPS:
        items = fn(features, meta)
        grouped[group] = [asdict(e) for e in items]
        flat.extend(items)

    risk_w = sum(SEVERITY_WEIGHT[e.severity] for e in flat if e.direction == "risk")
    trust_w = sum(SEVERITY_WEIGHT[e.severity] for e in flat if e.direction == "trust")
    raw = (risk_w - 0.8 * trust_w) / 14.0
    rule_score = round(float(max(0.0, min(1.0, raw)) * 100), 1)

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    top = sorted([e for e in flat if e.direction == "risk"],
                 key=lambda e: order[e.severity])[:5]

    return {
        "grouped": grouped,
        "rule_risk_score": rule_score,
        "risk_signal_count": sum(1 for e in flat if e.direction == "risk"),
        "trust_signal_count": sum(1 for e in flat if e.direction == "trust"),
        "top_reasons": [asdict(e) for e in top],
    }


def risk_band(probability: float) -> str:
    if probability >= 0.80:
        return "Critical"
    if probability >= 0.60:
        return "High"
    if probability >= 0.35:
        return "Moderate"
    if probability >= 0.15:
        return "Low"
    return "Minimal"


def recommendation(probability: float, evidence: dict) -> str:
    band = risk_band(probability)
    critical = [e for e in evidence["top_reasons"] if e["severity"] == "critical"]
    if band == "Critical":
        lead = "Do not install this app."
    elif band == "High":
        lead = "Avoid installing this app unless you can verify the publisher independently."
    elif band == "Moderate":
        lead = "Verify the publisher before installing."
    elif band == "Low":
        lead = "No strong indicators of fraud, but review the permissions before installing."
    else:
        lead = "This app matches the profile of a legitimate listing."
    if critical:
        return f"{lead} Most serious finding: {critical[0]['signal'].lower()}."
    return lead
