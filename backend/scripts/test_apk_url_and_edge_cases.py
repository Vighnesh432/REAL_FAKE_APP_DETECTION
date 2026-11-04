#!/usr/bin/env python3
"""
Covers the parts of the spec test_identity_verification.py doesn't:
  - invalid / corrupt APK files
  - a direct .apk download link that fails (network error, timeout, non-APK content)
  - a direct .apk download link that succeeds and gets identity-verified exactly like
    an upload
  - the SSRF guard that stops a user-supplied URL from reaching internal addresses

Network calls are mocked (unittest.mock), not real HTTP -- this sandbox's network is
allowlisted and cannot reach arbitrary hosts, and a real localhost/private-IP test
would be rejected by the SSRF guard itself (correctly). Mocking `requests.Session.get`
tests the actual download/parsing/identity logic without depending on either.

Run from backend/: python scripts/test_apk_url_and_edge_cases.py
"""
import datetime
import sys
import zipfile
from io import BytesIO
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import NameOID

from app.ml.apk import ApkParseError, analyse_apk
from app.ml.apk_download import ApkDownloadError, _is_public_host, fetch_apk_bytes, looks_like_apk_url

NOTES_MANIFEST = b"""<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.notesapp">
  <uses-permission android:name="android.permission.INTERNET"/>
  <application android:label="Simple Notes"/>
</manifest>
"""


def _build_signed_apk(manifest: bytes) -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Notes Dev")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .sign(key, hashes.SHA256())
    )
    pkcs7_der = (
        pkcs7.PKCS7SignatureBuilder(data=manifest).add_signer(cert, key, hashes.SHA256())
        .sign(serialization.Encoding.DER, [pkcs7.PKCS7Options.Binary, pkcs7.PKCS7Options.DetachedSignature])
    )
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n")
        zf.writestr("META-INF/CERT.RSA", pkcs7_der)
        zf.writestr("AndroidManifest.xml", manifest)
        zf.writestr("classes.dex", b"placeholder")
    return buf.getvalue()


def test_invalid_apk_files():
    print("\n=== Invalid APK files ===")
    for label, data in [
        ("empty file", b""),
        ("random garbage bytes", b"not a zip file at all, just text pretending to be one"),
        ("valid zip but no AndroidManifest.xml", _zip_without_manifest()),
    ]:
        try:
            analyse_apk(data)
            raise AssertionError(f"{label}: expected ApkParseError, got no error")
        except ApkParseError as e:
            print(f"  [{label}] correctly rejected: {e}")


def _zip_without_manifest() -> bytes:
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("readme.txt", "this zip has no manifest")
    return buf.getvalue()


def test_ssrf_guard():
    print("\n=== SSRF guard (host resolution checks) ===")
    # Public IPs / hostnames -- should be allowed through
    for host in ["8.8.8.8", "1.1.1.1"]:
        assert _is_public_host(host), f"{host} should be treated as public"
        print(f"  [{host}] correctly allowed (public)")
    # Private / internal ranges -- must be refused
    for host in ["127.0.0.1", "10.0.0.5", "192.168.1.1", "169.254.169.254", "0.0.0.0"]:
        assert not _is_public_host(host), f"{host} should be REFUSED as private/internal"
        print(f"  [{host}] correctly refused (private/internal)")


def test_looks_like_apk_url():
    print("\n=== URL classification ===")
    assert looks_like_apk_url("https://example.com/files/app-release.apk")
    assert not looks_like_apk_url("https://example.com/app-page.html")
    assert not looks_like_apk_url("https://play.google.com/store/apps/details?id=com.whatsapp")
    print("  .apk links vs. listing/website links classified correctly")


def _mock_response(status_code=200, content=b"", headers=None):
    resp = mock.Mock()
    resp.status_code = status_code
    resp.headers = headers or {}
    resp.iter_content = lambda chunk_size=1: [content[i:i + chunk_size] for i in range(0, len(content), chunk_size)]
    resp.close = lambda: None
    return resp


def test_download_success():
    print("\n=== Direct .apk link: successful download ===")
    apk_bytes = _build_signed_apk(NOTES_MANIFEST)
    fake_resp = _mock_response(200, apk_bytes, {"Content-Type": "application/vnd.android.package-archive"})
    with mock.patch("requests.Session.get", return_value=fake_resp):
        data, meta = fetch_apk_bytes("https://example.com/notes-app.apk")
    assert data == apk_bytes
    static = analyse_apk(data)
    assert static["package_name"] == "com.example.notesapp"
    print(f"  Downloaded {meta['bytes']} bytes, package resolved to {static['package_name']}")


def test_download_network_failure():
    print("\n=== Direct .apk link: connection failure ===")
    import requests
    with mock.patch("requests.Session.get", side_effect=requests.exceptions.ConnectionError("refused")):
        try:
            fetch_apk_bytes("https://example.com/notes-app.apk")
            raise AssertionError("expected ApkDownloadError")
        except ApkDownloadError as e:
            print(f"  Correctly raised ApkDownloadError: {e}")


def test_download_oversized():
    print("\n=== Direct .apk link: server claims an oversized file ===")
    fake_resp = _mock_response(200, b"", {"Content-Length": str(500 * 1024 * 1024)})
    with mock.patch("requests.Session.get", return_value=fake_resp):
        try:
            fetch_apk_bytes("https://example.com/huge.apk")
            raise AssertionError("expected ApkDownloadError for oversized file")
        except ApkDownloadError as e:
            print(f"  Correctly refused: {e}")


def test_download_non_apk_content():
    print("\n=== Direct .apk link: server returns an HTML error page, not an APK ===")
    html = b"<html><body>404 not found</body></html>"
    fake_resp = _mock_response(200, html, {"Content-Type": "text/html"})
    with mock.patch("requests.Session.get", return_value=fake_resp):
        data, _meta = fetch_apk_bytes("https://example.com/gone.apk")
    try:
        analyse_apk(data)
        raise AssertionError("expected ApkParseError for HTML content")
    except ApkParseError as e:
        print(f"  Downloaded fine, but correctly rejected at parse time: {e}")


def main():
    test_invalid_apk_files()
    test_ssrf_guard()
    test_looks_like_apk_url()
    test_download_success()
    test_download_network_failure()
    test_download_oversized()
    test_download_non_apk_content()
    print("\nAll edge-case tests passed.")


if __name__ == "__main__":
    main()
