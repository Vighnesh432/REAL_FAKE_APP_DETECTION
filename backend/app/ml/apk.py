import hashlib
import re
import struct
import zipfile
from io import BytesIO

from .apk_signature import extract_signing_identity

_STRING_POOL_TYPE = 0x001C
_UTF8_FLAG = 1 << 8

PERMISSION_RE = re.compile(r"^android\.permission\.([A-Z_0-9]+)$")
CUSTOM_PERMISSION_RE = re.compile(r"^[a-z][a-z0-9_]*(\.[a-z0-9_]+)+\.permission\.[A-Z_0-9]+$")
PACKAGE_RE = re.compile(r"^[a-z][a-z0-9_]*(\.[a-z0-9_]+){1,6}$")


class ApkParseError(ValueError):
    pass


def _read_string_pool(data: bytes) -> list[str]:
    if len(data) < 8:
        raise ApkParseError("Manifest is too small to be valid.")

    pos, pool_start = 8, None
    while pos + 8 <= len(data):
        ctype, _hsize, csize = struct.unpack_from("<HHI", data, pos)
        if csize <= 0 or pos + csize > len(data):
            break
        if ctype == _STRING_POOL_TYPE:
            pool_start = pos
            break
        pos += csize
    if pool_start is None:
        raise ApkParseError("No string pool found — this does not look like a binary manifest.")

    _t, _h, chunk_size = struct.unpack_from("<HHI", data, pool_start)
    string_count, _style_count, flags, strings_start, _styles_start = struct.unpack_from(
        "<IIIII", data, pool_start + 8)
    is_utf8 = bool(flags & _UTF8_FLAG)

    offsets_at = pool_start + 28
    data_at = pool_start + strings_start
    end = min(pool_start + chunk_size, len(data))

    out: list[str] = []
    for i in range(min(string_count, 200_000)):
        off_pos = offsets_at + i * 4
        if off_pos + 4 > len(data):
            break
        (offset,) = struct.unpack_from("<I", data, off_pos)
        p = data_at + offset
        if p >= end:
            continue
        try:
            out.append(_decode_utf8(data, p, end) if is_utf8 else _decode_utf16(data, p, end))
        except Exception:
            continue
    return out


def _decode_len_utf8(data: bytes, p: int) -> tuple[int, int]:
    b = data[p]
    if b & 0x80:
        return ((b & 0x7F) << 8) | data[p + 1], p + 2
    return b, p + 1


def _decode_utf8(data: bytes, p: int, end: int) -> str:
    _chars, p = _decode_len_utf8(data, p)
    byte_len, p = _decode_len_utf8(data, p)
    return data[p: min(p + byte_len, end)].decode("utf-8", errors="replace")


def _decode_utf16(data: bytes, p: int, end: int) -> str:
    (length,) = struct.unpack_from("<H", data, p)
    p += 2
    if length & 0x8000:
        (low,) = struct.unpack_from("<H", data, p)
        length = ((length & 0x7FFF) << 16) | low
        p += 2
    return data[p: min(p + length * 2, end)].decode("utf-16-le", errors="replace")


def analyse_apk(apk_bytes: bytes) -> dict:
    try:
        zf = zipfile.ZipFile(BytesIO(apk_bytes))
    except zipfile.BadZipFile:
        raise ApkParseError("That file is not a valid APK. An APK is a ZIP archive.")

    names = set(zf.namelist())
    if "AndroidManifest.xml" not in names:
        raise ApkParseError("No AndroidManifest.xml inside the archive — not an Android package.")

    manifest = zf.read("AndroidManifest.xml")
    if manifest[:5] == b"<?xml" or manifest[:9] == b"<manifest":
        strings = re.findall(r'"([^"]{3,200})"', manifest.decode("utf-8", errors="replace"))
    else:
        strings = _read_string_pool(manifest)

    permissions, custom_permissions = set(), set()
    for s in strings:
        s = s.strip()
        if PERMISSION_RE.match(s):
            permissions.add(PERMISSION_RE.match(s).group(1))
        elif CUSTOM_PERMISSION_RE.match(s):
            custom_permissions.add(s)

    candidates = [
        s for s in strings
        if PACKAGE_RE.match(s) and not s.startswith(("android.", "androidx.", "java.", "kotlin."))
        and "permission" not in s and "intent" not in s and "action" not in s
    ]
    package_name = min(candidates, key=len) if candidates else ""

    total = sum(i.file_size for i in zf.infolist())
    native_libs = sorted({
        n.split("/")[1] for n in names if n.startswith("lib/") and n.count("/") >= 2
    })

    # Real signing-certificate identity (see apk_signature.py). `is_signed` below is
    # kept only as a structural sanity check ("did this package go through a signing
    # step at all") -- it is TRUE for every installable APK, including every MOD APK,
    # because Android requires a signature (even a self-generated one) to install
    # anything. It carries no information about WHO signed it, so it must never be
    # read as a genuineness signal on its own. Use certificate_fingerprints /
    # app.ml.identity.verify_apk_identity() for that.
    signing = extract_signing_identity(apk_bytes)

    return {
        "package_name": package_name,
        "permissions": sorted(permissions),
        "custom_permissions": sorted(custom_permissions),
        "permission_count": len(permissions),
        "size_mb": round(total / (1024 * 1024), 2),
        "compressed_size_mb": round(len(apk_bytes) / (1024 * 1024), 2),
        "file_count": len(names),
        "has_native_libs": bool(native_libs),
        "native_abis": native_libs,
        "is_signed": bool(signing["signing_schemes"]),
        "has_v1_signature": any(n == "META-INF/MANIFEST.MF" for n in names),
        "dex_count": sum(1 for n in names if n.endswith(".dex")),
        "extracted_strings": len(strings),
        "sha256": hashlib.sha256(apk_bytes).hexdigest(),
        "signing_schemes": signing["signing_schemes"],
        "certificates": signing["certificates"],
        "certificate_fingerprints": signing["certificate_fingerprints"],
        "signature_errors": signing["signature_errors"],
    }
