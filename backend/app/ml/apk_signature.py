"""
Extracts the real signing-certificate identity of an APK.

Android requires every installable APK to be cryptographically signed, using one (or
more) of three schemes: v1 (JAR signing -- a PKCS#7 SignedData block under
META-INF/*.RSA, *.DSA or *.EC), v2, and v3 (the "APK Signing Block", a binary
structure sitting immediately before the ZIP central directory). All three embed the
signer's actual X.509 certificate(s), and none of them can be produced without the
original private key -- unlike a package name or a manifest permission, which a
repackager can simply copy byte-for-byte into a modified build.

This module extracts those certificates and reduces each one to its SHA-256
fingerprint: the same value `apksigner verify --print-certs` or Google Play Protect
would show, and the value this project pins in known_signers.json to recognise a
publisher's real, unmodified build.

It does NOT decide whether an app is genuine -- see identity.py for that. This module
only answers "who cryptographically signed this exact file", which a MOD/repackaged
APK cannot fake without also defeating the check that relies on it.

No androguard dependency, consistent with apk.py: v1 parsing uses the `cryptography`
library (already a project dependency) directly against the DER PKCS#7 block; v2/v3
parsing is ~80 lines of manual binary parsing against Android's own published format,
the same approach already used for the binary AndroidManifest.xml parser.
"""

from __future__ import annotations

import struct
import zipfile
from dataclasses import dataclass, field
from io import BytesIO

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import pkcs7

_V2_BLOCK_ID = 0x7109871A
_V3_BLOCK_ID = 0xF05368C0
_SIG_BLOCK_MAGIC = b"APK Sig Block 42"
_EOCD_SIG = b"PK\x05\x06"


@dataclass
class _SigningIdentity:
    schemes: list = field(default_factory=list)
    certificates: list = field(default_factory=list)
    errors: list = field(default_factory=list)

    def as_dict(self) -> dict:
        seen, fingerprints = set(), []
        for c in self.certificates:
            fp = c["fingerprint_sha256"]
            if fp not in seen:
                seen.add(fp)
                fingerprints.append(fp)
        return {
            "signing_schemes": sorted(set(self.schemes)),
            "certificates": self.certificates,
            "certificate_fingerprints": fingerprints,
            "signature_errors": self.errors,
        }


def _cert_info(cert: "x509.Certificate", scheme: str) -> dict:
    subject = cert.subject.rfc4514_string()
    issuer = cert.issuer.rfc4514_string()
    try:
        not_before = cert.not_valid_before_utc.isoformat()
        not_after = cert.not_valid_after_utc.isoformat()
    except AttributeError:  # older cryptography versions
        not_before = cert.not_valid_before.isoformat()
        not_after = cert.not_valid_after.isoformat()
    return {
        "scheme": scheme,
        "subject": subject,
        "issuer": issuer,
        "self_signed": subject == issuer,
        "serial_number": format(cert.serial_number, "x"),
        "not_valid_before": not_before,
        "not_valid_after": not_after,
        "fingerprint_sha256": cert.fingerprint(hashes.SHA256()).hex(),
    }


def _extract_v1(names: set, zf: zipfile.ZipFile, out: _SigningIdentity) -> None:
    block_files = sorted(
        n for n in names if n.startswith("META-INF/") and n.endswith((".RSA", ".DSA", ".EC"))
    )
    for name in block_files:
        try:
            certs = pkcs7.load_der_pkcs7_certificates(zf.read(name))
        except Exception as e:
            out.errors.append(f"v1 signature block '{name}' could not be parsed: {e}")
            continue
        if certs:
            out.schemes.append("v1")
        for cert in certs:
            out.certificates.append(_cert_info(cert, "v1"))


def _read_lp(buf: bytes, pos: int) -> tuple[bytes, int]:
    """A 4-byte little-endian length prefix followed by that many bytes."""
    if pos + 4 > len(buf):
        raise ValueError("truncated length prefix")
    (length,) = struct.unpack_from("<I", buf, pos)
    pos += 4
    if length < 0 or pos + length > len(buf):
        raise ValueError("length-prefixed block runs past the end of its container")
    return buf[pos: pos + length], pos + length


def _signer_certs(signer_block: bytes) -> list:
    """signer := lp(signed_data) lp(signatures) lp(public_key)
    signed_data := lp(digests) lp(certificates) lp(additional_attributes)
    certificates := (lp(x509_der))*
    """
    signed_data, _ = _read_lp(signer_block, 0)
    pos = 0
    _digests, pos = _read_lp(signed_data, pos)
    certs_block, pos = _read_lp(signed_data, pos)
    certs, cpos = [], 0
    while cpos < len(certs_block):
        cert_der, cpos = _read_lp(certs_block, cpos)
        certs.append(cert_der)
    return certs


def _extract_v2_v3(apk_bytes: bytes, out: _SigningIdentity) -> None:
    eocd_idx = apk_bytes.rfind(_EOCD_SIG)
    if eocd_idx == -1:
        out.errors.append("No End-Of-Central-Directory record found; not a well-formed ZIP.")
        return
    if eocd_idx + 20 > len(apk_bytes):
        out.errors.append("End-Of-Central-Directory record is truncated.")
        return
    (cd_offset,) = struct.unpack_from("<I", apk_bytes, eocd_idx + 16)
    if cd_offset < 24 or cd_offset > len(apk_bytes):
        out.errors.append("Central directory offset is out of range; ZIP structure looks corrupted.")
        return

    if apk_bytes[cd_offset - 16: cd_offset] != _SIG_BLOCK_MAGIC:
        return  # no v2/v3 block -- normal for a v1-only signed APK

    (size2,) = struct.unpack_from("<Q", apk_bytes, cd_offset - 24)
    block_start = cd_offset - 8 - size2
    if block_start < 0 or block_start + 8 > len(apk_bytes):
        out.errors.append("APK Signing Block size field is inconsistent; skipping v2/v3 parse.")
        return
    (size1,) = struct.unpack_from("<Q", apk_bytes, block_start)
    if size1 != size2:
        out.errors.append("APK Signing Block's two size fields disagree; the block may be tampered with.")
        return

    pairs = apk_bytes[block_start + 8: cd_offset - 24]
    pos = 0
    while pos + 12 <= len(pairs):
        (pair_len,) = struct.unpack_from("<Q", pairs, pos)
        pos += 8
        if pair_len < 4 or pos + pair_len > len(pairs):
            break
        (block_id,) = struct.unpack_from("<I", pairs, pos)
        value = pairs[pos + 4: pos + pair_len]
        pos += pair_len

        scheme = {_V2_BLOCK_ID: "v2", _V3_BLOCK_ID: "v3"}.get(block_id)
        if scheme is None:
            continue
        try:
            signers_blob, _ = _read_lp(value, 0)
        except Exception as e:
            out.errors.append(f"{scheme} block could not be parsed: {e}")
            continue

        spos, found_any = 0, False
        while spos < len(signers_blob):
            try:
                signer, spos = _read_lp(signers_blob, spos)
                for cert_der in _signer_certs(signer):
                    cert = x509.load_der_x509_certificate(cert_der)
                    out.certificates.append(_cert_info(cert, scheme))
                    found_any = True
            except Exception as e:
                out.errors.append(f"A {scheme} signer record could not be parsed: {e}")
                break
        if found_any:
            out.schemes.append(scheme)


def extract_signing_identity(apk_bytes: bytes) -> dict:
    """Returns {signing_schemes, certificates, certificate_fingerprints, signature_errors}.

    Never raises: a file that can't be parsed comes back with empty certificates and a
    human-readable reason in signature_errors, so a malformed or exotic APK degrades
    the *confidence* of identity verification rather than crashing the whole scan.
    """
    out = _SigningIdentity()
    try:
        zf = zipfile.ZipFile(BytesIO(apk_bytes))
        names = set(zf.namelist())
    except zipfile.BadZipFile:
        out.errors.append("Not a valid ZIP/APK archive.")
        return out.as_dict()

    _extract_v1(names, zf, out)
    try:
        _extract_v2_v3(apk_bytes, out)
    except Exception as e:
        out.errors.append(f"v2/v3 signing block parse failed: {e}")

    return out.as_dict()
