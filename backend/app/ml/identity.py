"""
Separates "this file's manifest claims an official package name" from "this file is
proven to be the official publisher's build" -- the distinction the ML classifier and
the old rule engine collapsed into one.

`is_official_app()` in features.py checks a STRING: does the manifest's package name
equal a known brand's package identifier. On a Play Store *listing*, that check is
meaningful -- the Store enforces package-name uniqueness across its own namespace, so
two different publishers cannot both own "com.whatsapp". But on a sideloaded *APK
file*, nothing enforces that at all. A repackager decompiles the real app, edits it,
and re-signs it -- and deliberately keeps the original package name unchanged, both
because there is no reason to change it and because doing so lets the modified build
install as an "update" over the genuine one. So for an uploaded APK, a package-name
match proves nothing about who built the file.

The one thing a repackager cannot copy is the ORIGINAL signing certificate, because
producing a valid signature requires the original private key (see apk_signature.py).
This module compares certificate(s) actually extracted from the APK against a short,
explicitly-curated registry of fingerprints known to belong to a publisher's real build
(known_signers.json) and returns a verdict that is independent of the ML/rule blend.

Verdicts:
  verified_official            Package matches a tracked brand's official identifier
                                AND a certificate found in the file matches one pinned
                                for that package. The only state allowed to increase
                                trust in predict.py.
  certificate_mismatch         Package matches a tracked brand's official identifier,
                                but none of the certificates found match a pinned
                                fingerprint. Near-conclusive evidence of a repackaged,
                                resigned, or otherwise non-official build -- this is
                                exactly what a MOD APK produces.
  unverified_no_pin            Package matches a tracked brand, but no fingerprint has
                                been pinned for it yet. Explicitly neutral: nothing to
                                compare against, so no trust and no penalty.
  unverifiable_no_certificate  Package matches a tracked brand, but no signing
                                certificate could be extracted from the file at all. A
                                validly built, installable APK always yields at least
                                one, so this is treated as a risk signal.
  third_party                  Package does not match any tracked brand's official
                                identifier. Identity verification does not apply here;
                                ordinary name-similarity / ML / rule checks run as usual.
"""

from __future__ import annotations

import json
from pathlib import Path

from .features import OFFICIAL_PACKAGES

REGISTRY_PATH = Path(__file__).resolve().parent / "known_signers.json"


def _load_registry() -> dict:
    try:
        data = json.loads(REGISTRY_PATH.read_text())
        return {pkg: set(fps) for pkg, fps in data.get("signers", {}).items()}
    except Exception:
        return {}


def _claimed_brand(package: str) -> str | None:
    """Only ever matches when `package` is LITERALLY a brand's official package
    identifier -- i.e. only when a certificate check is meaningful. A name that merely
    *resembles* a brand while using some other package is impersonation-by-name, not a
    claim this module can verify against a pinned certificate; that case is left to the
    ordinary brand-similarity rule in explain.py, unchanged."""
    pkg = str(package).strip()
    for brand, pkgs in OFFICIAL_PACKAGES.items():
        if pkg in pkgs:
            return brand
    return None


def verify_apk_identity(package_name: str, certificate_fingerprints: list) -> dict:
    pkg = str(package_name).strip()
    brand = _claimed_brand(pkg)

    if not brand:
        return {"identity_verdict": "third_party", "claimed_brand": None,
                "matched_fingerprint": None, "pinned_available": False}

    pinned = _load_registry().get(pkg, set())

    if not certificate_fingerprints:
        return {"identity_verdict": "unverifiable_no_certificate", "claimed_brand": brand,
                "matched_fingerprint": None, "pinned_available": bool(pinned)}

    if not pinned:
        return {"identity_verdict": "unverified_no_pin", "claimed_brand": brand,
                "matched_fingerprint": None, "pinned_available": False}

    matched = next((fp for fp in certificate_fingerprints if fp in pinned), None)
    if matched:
        return {"identity_verdict": "verified_official", "claimed_brand": brand,
                "matched_fingerprint": matched, "pinned_available": True}

    return {"identity_verdict": "certificate_mismatch", "claimed_brand": brand,
            "matched_fingerprint": None, "pinned_available": True}
