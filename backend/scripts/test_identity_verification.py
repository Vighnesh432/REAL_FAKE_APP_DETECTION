#!/usr/bin/env python3
"""
Regression test for the certificate-based identity verification layer.

Builds small synthetic APKs entirely in-memory (no real WhatsApp/Instagram binaries
or third-party MOD APKs are used or needed -- fetching those from the internet is
neither reachable from a sandboxed environment nor something this project should be
sourcing) and drives them through the exact same code path a real upload takes:
apk.analyse_apk() -> identity.verify_apk_identity() -> predict.predict_one().

The fixtures reproduce the precise scenario in question: two files that declare the
IDENTICAL package name and IDENTICAL manifest permissions, differing only in which
private key signed them -- exactly what a real app vs. its MOD/repackaged clone looks
like at the manifest level. If this passes, the mechanism generalises to any real APK,
because PKCS#7 parsing does not care whether the certificate is 'real' or synthetic.

Run from backend/: python scripts/test_identity_verification.py
"""
import datetime
import json
import struct
import sys
import zipfile
from io import BytesIO
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import NameOID

from app.ml import predict as ml
from app.ml.apk import analyse_apk
from app.ml.identity import REGISTRY_PATH

WHATSAPP_MANIFEST = b"""<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.whatsapp">
  <uses-permission android:name="android.permission.INTERNET"/>
  <uses-permission android:name="android.permission.READ_CONTACTS"/>
  <uses-permission android:name="android.permission.CAMERA"/>
  <uses-permission android:name="android.permission.RECORD_AUDIO"/>
  <uses-permission android:name="android.permission.READ_PHONE_STATE"/>
  <uses-permission android:name="android.permission.VIBRATE"/>
  <uses-permission android:name="android.permission.POST_NOTIFICATIONS"/>
  <application android:label="WhatsApp"/>
</manifest>
"""

INSTAGRAM_MANIFEST = b"""<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.instagram.android">
  <uses-permission android:name="android.permission.INTERNET"/>
  <uses-permission android:name="android.permission.CAMERA"/>
  <uses-permission android:name="android.permission.READ_MEDIA_IMAGES"/>
  <application android:label="Instagram"/>
</manifest>
"""

NOTES_MANIFEST = b"""<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.notesapp">
  <uses-permission android:name="android.permission.INTERNET"/>
  <uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE"/>
  <application android:label="Simple Notes"/>
</manifest>
"""

IMPERSONATOR_MANIFEST = b"""<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.fake.whatsapp2">
  <uses-permission android:name="android.permission.INTERNET"/>
  <uses-permission android:name="android.permission.READ_SMS"/>
  <uses-permission android:name="android.permission.SEND_SMS"/>
  <uses-permission android:name="android.permission.SYSTEM_ALERT_WINDOW"/>
  <application android:label="WhatsApp Plus Gold"/>
</manifest>
"""


def _make_cert(common_name: str):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject).issuer_name(issuer).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .sign(key, hashes.SHA256())
    )
    return key, cert


def _build_apk(manifest_bytes: bytes, key, cert) -> bytes:
    pkcs7_der = (
        pkcs7.PKCS7SignatureBuilder(data=manifest_bytes)
        .add_signer(cert, key, hashes.SHA256())
        .sign(serialization.Encoding.DER,
              [pkcs7.PKCS7Options.Binary, pkcs7.PKCS7Options.DetachedSignature])
    )
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n")
        zf.writestr("META-INF/CERT.RSA", pkcs7_der)
        zf.writestr("AndroidManifest.xml", manifest_bytes)
        zf.writestr("classes.dex", b"dex-placeholder")
    return buf.getvalue()


def _fingerprint_of(cert) -> str:
    return cert.fingerprint(hashes.SHA256()).hex()


def _pin(package: str, fingerprint: str) -> None:
    registry = json.loads(REGISTRY_PATH.read_text())
    registry.setdefault("signers", {})[package] = [fingerprint]
    REGISTRY_PATH.write_text(json.dumps(registry, indent=2))


def _reset_registry() -> None:
    REGISTRY_PATH.write_text(json.dumps({"_readme": "test", "signers": {}}, indent=2))


def _run(label: str, manifest: bytes, key, cert, app_name: str, category="Communication"):
    apk_bytes = _build_apk(manifest, key, cert)
    static = analyse_apk(apk_bytes)
    payload = {
        "app_name": app_name, "package_name": static["package_name"], "category": category,
        "description": (
            "Send messages, make voice and video calls, and share photos, videos and "
            "documents with friends and family across the world. Conversations are "
            "protected end-to-end so nobody else can read them. Works reliably even on "
            "a slow connection and uses very little data in the background."
        ),
        "reviews": [], "permissions": static["permissions"],
        "rating": 0.0, "rating_count": 0, "installs": 0, "size_mb": static["size_mb"],
        "price": 0.0, "days_since_update": 0, "app_age_days": 0, "developer_app_count": 0,
        "has_developer_website": 0, "has_privacy_policy": 0,
    }
    result = ml.predict_one(payload, apk_static=static)
    ev = result["evidence"]
    print(f"\n=== {label} ===")
    print(f"  package_name        : {static['package_name']}")
    print(f"  cert fingerprint    : {static['certificate_fingerprints']}")
    print(f"  signing schemes     : {static['signing_schemes']}")
    print(f"  identity_verdict    : {ev.get('identity_verdict')}")
    print(f"  verdict             : {result['verdict']}  (risk_score={result['risk_score']})")
    print(f"  model_probability   : {result['model_probability']}   rule_risk_score: {ev['rule_risk_score']}")
    top = [f"{e['signal']} [{e['severity']}/{e['direction']}]" for e in ev["top_reasons"]]
    print(f"  top_reasons         : {top}")
    return result, static


def main():
    _reset_registry()

    key_a, cert_a = _make_cert("Meta Platforms, Inc.")   # "the real one"
    key_b, cert_b = _make_cert("Unknown Repackager")     # "the MOD"
    key_c, cert_c = _make_cert("Notes Dev")
    key_d, cert_d = _make_cert("Scammer")
    key_e, cert_e = _make_cert("Instagram-ish")

    fp_a = _fingerprint_of(cert_a)
    _pin("com.whatsapp", fp_a)
    print(f"Pinned com.whatsapp -> {fp_a}  (simulating an admin who ran pin_signer.py "
          f"against a real, adb-pulled WhatsApp APK)")

    r1, _ = _run("1. Official WhatsApp (signed with the pinned cert)", WHATSAPP_MANIFEST,
                 key_a, cert_a, "WhatsApp")
    assert r1["evidence"]["identity_verdict"] == "verified_official", r1["evidence"]["identity_verdict"]
    assert r1["verdict"] == "Genuine", r1

    r2, _ = _run("2. WhatsApp MOD (same package, different signing key)", WHATSAPP_MANIFEST,
                 key_b, cert_b, "WhatsApp")
    assert r2["evidence"]["identity_verdict"] == "certificate_mismatch", r2["evidence"]["identity_verdict"]
    assert r2["verdict"] == "Fake", r2
    assert r2["risk_score"] >= 90, r2["risk_score"]

    r3, _ = _run("3. Instagram, official package, NOT yet pinned by any admin",
                 INSTAGRAM_MANIFEST, key_e, cert_e, "Instagram")
    assert r3["evidence"]["identity_verdict"] == "unverified_no_pin", r3["evidence"]["identity_verdict"]

    r4, _ = _run("4. Genuine unrelated third-party app", NOTES_MANIFEST, key_c, cert_c,
                 "Simple Notes", category="Productivity")
    assert r4["evidence"]["identity_verdict"] == "third_party", r4["evidence"]["identity_verdict"]

    r5, _ = _run("5. Classic impersonator: 'WhatsApp Plus Gold', different package",
                 IMPERSONATOR_MANIFEST, key_d, cert_d, "WhatsApp Plus Gold")
    assert r5["evidence"]["identity_verdict"] == "third_party", r5["evidence"]["identity_verdict"]
    signals = {e["signal"] for e in r5["evidence"]["top_reasons"]}
    assert "Impersonates a known app" in signals, signals
    assert r5["verdict"] == "Fake", r5

    print("\nAll 5 identity-verification scenarios behaved as expected.")


if __name__ == "__main__":
    main()
