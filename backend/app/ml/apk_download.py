"""
Fetches the actual APK binary behind a direct download link, as opposed to a Play
Store *listing* URL (which play_store.py handles by scraping metadata, not a binary).

This exists specifically so a link to an .apk file gets its BINARY inspected --
signing certificate, manifest, permissions -- exactly the way an uploaded file does,
instead of being punted to the generic website-heuristics path (no ML/identity logic
at all) or silently trusted because nothing crashed.

Two things this module refuses to do quietly:
  1. Trust the download blindly. Network failures, timeouts, oversized responses, and
     redirect loops all raise ApkDownloadError with a specific reason. The caller
     (routers/predict.py) is expected to surface an explicit "could not verify"
     result for any of these -- never default to Genuine just because nothing raised.
  2. Let a user-supplied URL reach the server's own internal network. Because this
     runs server-side against an attacker-controlled URL, it resolves the hostname
     and refuses private/loopback/link-local/reserved addresses before connecting,
     and re-validates on every redirect hop (a classic SSRF surface otherwise).
"""
from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urljoin, urlparse

import requests

MAX_APK_BYTES = 150 * 1024 * 1024
CONNECT_TIMEOUT = 8
READ_TIMEOUT = 25
MAX_REDIRECTS = 5
USER_AGENT = "FakeAppDetector/1.0 (+security-scan)"


class ApkDownloadError(ValueError):
    pass


def _is_public_host(hostname: str) -> bool:
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror as e:
        raise ApkDownloadError(f"Could not resolve host '{hostname}': {e}")
    for _family, _type, _proto, _canon, sockaddr in infos:
        ip = ipaddress.ip_address(sockaddr[0])
        if (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_reserved or ip.is_multicast or ip.is_unspecified):
            return False
    return True


def _validate_url(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ApkDownloadError(f"Unsupported URL scheme '{parsed.scheme or '(none)'}'.")
    if not parsed.hostname:
        raise ApkDownloadError("URL has no host.")
    if not _is_public_host(parsed.hostname):
        raise ApkDownloadError("That host resolves to a private or internal address and is refused.")
    return url


def looks_like_apk_url(url: str) -> bool:
    return urlparse(url).path.lower().endswith(".apk")


def fetch_apk_bytes(url: str) -> tuple[bytes, dict]:
    """Returns (apk_bytes, meta). Raises ApkDownloadError on any failure -- there is
    no partial-success return value, so a caller can never mistake a failed fetch for
    a verified one."""
    current = _validate_url(url)
    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})

    for _ in range(MAX_REDIRECTS + 1):
        try:
            resp = session.get(current, stream=True, allow_redirects=False,
                                timeout=(CONNECT_TIMEOUT, READ_TIMEOUT))
        except requests.RequestException as e:
            raise ApkDownloadError(f"Could not reach that URL: {e}")

        if resp.status_code in (301, 302, 303, 307, 308):
            location = resp.headers.get("Location")
            resp.close()
            if not location:
                raise ApkDownloadError("Server redirected without a Location header.")
            current = _validate_url(urljoin(current, location))
            continue

        if resp.status_code != 200:
            resp.close()
            raise ApkDownloadError(f"Server returned HTTP {resp.status_code}.")

        content_length = resp.headers.get("Content-Length")
        if content_length and int(content_length) > MAX_APK_BYTES:
            resp.close()
            raise ApkDownloadError(
                f"File is {int(content_length) / 1e6:.0f} MB, over the "
                f"{MAX_APK_BYTES / 1e6:.0f} MB limit.")

        chunks, total = [], 0
        try:
            for chunk in resp.iter_content(chunk_size=1 << 16):
                total += len(chunk)
                if total > MAX_APK_BYTES:
                    raise ApkDownloadError(
                        f"File exceeded the {MAX_APK_BYTES / 1e6:.0f} MB limit while downloading.")
                chunks.append(chunk)
        except requests.RequestException as e:
            raise ApkDownloadError(f"Download interrupted: {e}")
        finally:
            resp.close()

        content_type = resp.headers.get("Content-Type", "")
        return b"".join(chunks), {"final_url": current, "content_type": content_type, "bytes": total}

    raise ApkDownloadError(f"Too many redirects (over {MAX_REDIRECTS}).")
