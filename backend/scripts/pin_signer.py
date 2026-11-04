#!/usr/bin/env python3
"""
Pin a package's real signing-certificate fingerprint into known_signers.json.

This is the ONLY supported way to populate the trusted-signer registry. Do not
hand-edit known_signers.json with a fingerprint copied from a website, forum post, or
search result -- this tool exists specifically so every pinned fingerprint traces back
to an APK file you personally examined and vouch for. A wrong fingerprint in that file
is worse than none: it would make the system actively vouch for a fake app.

Trusted sources for the input APK, in order of preference:
  1. Pulled directly off a device where the app was installed from the Play Store:
       adb shell pm path <package_name>      # prints e.g. /data/app/.../base.apk
       adb pull <path-printed-above> official.apk
  2. An .apk you built and signed yourself, or downloaded from Google's own Play
     Console tooling, if you are the app's publisher.

Do NOT use an APK downloaded from a third-party mirror or "APK download" site as the
seed for a pin -- that defeats the entire point of pinning a certificate.

Usage:
    python backend/scripts/pin_signer.py official.apk com.whatsapp
    python backend/scripts/pin_signer.py official.apk com.whatsapp --yes
"""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.ml.apk_signature import extract_signing_identity  # noqa: E402

REGISTRY_PATH = Path(__file__).resolve().parents[1] / "app" / "ml" / "known_signers.json"


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("apk_path", help="Path to a verified-source APK")
    ap.add_argument("package_name", help="Package identifier this certificate should be trusted for")
    ap.add_argument("--yes", action="store_true", help="skip the confirmation prompt")
    args = ap.parse_args()

    apk_bytes = Path(args.apk_path).read_bytes()
    identity = extract_signing_identity(apk_bytes)

    if identity["signature_errors"]:
        print("Warnings while reading the signature:")
        for e in identity["signature_errors"]:
            print(f"  - {e}")

    fps = identity["certificate_fingerprints"]
    if not fps:
        print("\nNo signing certificate could be extracted from this file. Refusing to pin anything.")
        sys.exit(1)

    print(f"\nFound {len(fps)} certificate(s) in {args.apk_path} "
          f"(schemes: {', '.join(identity['signing_schemes']) or 'none'}):")
    for cert in identity["certificates"]:
        print(f"  [{cert['scheme']}] {cert['fingerprint_sha256']}")
        print(f"      subject: {cert['subject']}")
        print(f"      valid:   {cert['not_valid_before']}  ->  {cert['not_valid_after']}")

    if not args.yes:
        prompt = (f"\nPin {'this' if len(fps) == 1 else 'these'} fingerprint(s) as trusted "
                  f"for '{args.package_name}'? [y/N] ")
        if input(prompt).strip().lower() != "y":
            print("Not pinned.")
            return

    registry = json.loads(REGISTRY_PATH.read_text()) if REGISTRY_PATH.exists() \
        else {"_readme": "", "signers": {}}
    already = set(registry.setdefault("signers", {}).get(args.package_name, []))
    new_ones = set(fps) - already
    registry["signers"][args.package_name] = sorted(already | set(fps))
    REGISTRY_PATH.write_text(json.dumps(registry, indent=2) + "\n")

    if already and new_ones:
        # Additive by design: pinning never removes a previously-trusted certificate,
        # so a legitimate signing-key rotation is handled by pinning the NEW key
        # alongside the old one (both verify as `verified_official` until you
        # deliberately remove the retired one from known_signers.json yourself).
        print(f"\n'{args.package_name}' already had {len(already)} pinned certificate(s). "
              f"Added {len(new_ones)} new one(s) -- both old and new now verify as official. "
              f"If the old key is confirmed retired, remove it from known_signers.json by hand.")
    elif already:
        print(f"\nNo new certificates to add -- '{args.package_name}' already trusts all {len(fps)} found here.")
    else:
        print(f"\nPinned {len(fps)} fingerprint(s) for '{args.package_name}' -> {REGISTRY_PATH}")


if __name__ == "__main__":
    main()
