# Architecture change: certificate-based identity verification

## Root cause

For an uploaded APK, exactly one thing was ever anchored to the actual binary: the
package name and permissions parsed from `AndroidManifest.xml`. Everything else the
classifier saw — app name, description, rating, install count — was either typed by
whoever uploaded the file or defaulted to zero. And the one binary-level check that
existed, `is_signed`, only asked "does a signature file exist" — true for every
installable APK, MOD or not, since Android requires *a* signature but not a *specific*
one.

`is_official_app(name, package)` then treated "manifest package name equals
`com.whatsapp`" as proof of authenticity. A repackager preserves the original package
name and permission set on purpose — it's what lets the modified build install as an
"update" over the real app — so both of those checks passed cleanly, and the one
signal that *couldn't* be copied (the signing certificate) was never inspected beyond
its bare presence. The rule engine ended up with only trust evidence and no risk
evidence for a resigned clone, which is exactly the "MOD APK reads as Genuine" bug.
A second, compounding issue: the "Upload APK" form let the uploader type in rating,
install count, and description by hand, and the pipeline used those numbers as if they
were fetched marketplace fact.

Neither of these is a threshold problem. No amount of reweighting the ML/rule blend
fixes it, because the features feeding that blend genuinely contained no signal that
distinguishes "same package name, same builder" from "same package name, different
builder."

## The fix

**A cryptographic identity layer, independent of the ML/rule blend, that only applies
to actual APK files:**

- `apk_signature.py` extracts the real signing certificate(s) from the APK — v1 (JAR
  signing, PKCS#7) via the `cryptography` library, and v2/v3 (the APK Signing Block, how
  modern real apps are signed) via a small binary parser against Android's published
  format — and reduces each to its SHA-256 fingerprint, the same value `apksigner
  verify --print-certs` shows.
- `known_signers.json` + `identity.py` compare that fingerprint against a small,
  explicitly-curated registry (package → trusted fingerprints), producing one of five
  verdicts: `verified_official`, `certificate_mismatch`, `unverified_no_pin`,
  `unverifiable_no_certificate`, `third_party`.
- `predict.py` treats `certificate_mismatch` as a **hard floor** (risk ≥ 93), not a
  weighted input — a mismatch is close to a proven fact, not a probability, so nothing
  else in the scan can pull it back to Genuine. `verified_official` is the *only* state
  allowed to raise trust, and only when no other risk signal fired either.
- `explain.py`'s old package-name-only trust shortcut is gone for the APK-upload path.
  It's kept, unchanged, for Play-Store-*listing* scans specifically — there, package-name
  uniqueness really is enforced by the Store itself; it just proves nothing about a
  sideloaded file. This is the "official package name" vs. "verified official APK"
  split.
- The Upload-APK route no longer feeds attacker-typed rating/installs into the model;
  those fields are now display-only and labeled unverified. `explain.py` gained a
  "no marketplace listing data" guard (and a `publisher_history_unknown` guard for the
  Play Store scraper's known always-zero fields) so removing that fabricated trust
  doesn't manufacture new false positives on a genuine upload.

**Why not fix this in the ML model instead:** it can't be. A repackager can make every
listing-style feature (permissions, description, name) byte-identical to the original
by construction. Certificate identity is a deterministic, cryptographic question, not
a statistical one — hence a separate gate, not a retrained model.

## Populating the registry

`known_signers.json` ships empty on purpose — no fingerprint is fabricated or
hand-typed from memory or a search result. Populate it with:

```
python backend/scripts/pin_signer.py official.apk com.whatsapp
```

...pointed at an APK pulled directly from a device where the real app is installed
from the Play Store (`adb shell pm path com.whatsapp` → `adb pull`). Until a package
is pinned, it's scored exactly like any other third-party app — no worse, no better.

## Two additions since the first version of this fix

**1. Direct `.apk` download links are now verified, not just Play Store listings.**
`routers/predict.py`'s `/predict/url` previously only knew "Play Store listing" vs.
"generic website" — a link straight to an `.apk` file fell into the website-heuristics
path, which has no ML/identity logic at all. `apk_download.py` now fetches the actual
bytes behind such a link and runs them through the identical identity-verification +
ML/rule pipeline as an uploaded file. If the download fails, times out, exceeds the
150MB cap, or isn't a valid APK once fetched, the result is an explicit third verdict,
**`"Unverified"`** — never a default to `"Genuine"`. Because this fetches a
user-supplied URL server-side, it also resolves the hostname and refuses
private/loopback/link-local/reserved addresses (and re-checks on every redirect hop)
before connecting, to close the obvious SSRF hole that kind of endpoint opens.

**2. Signing-key rotation is supported, explicitly.** `known_signers.json` always
stored a *list* of fingerprints per package, so this was structurally already
additive — `pin_signer.py` now says so out loud: pinning a second certificate for a
package that already has one keeps both trusted (a legitimate rotation), and only
tells you to remove the old one by hand once you've confirmed it's retired. Nothing
is ever silently overwritten.

## Verification

`backend/scripts/test_identity_verification.py` builds synthetic APKs in-memory (no
real or third-party MOD binaries used — this sandbox can't reach app stores or APK
mirror sites, and sourcing MOD APKs isn't something to automate regardless) with the
exact scenario in question: identical package name and permissions, different signing
key. All 5 cases pass:

| Case | Identity verdict | Verdict |
|---|---|---|
| Official WhatsApp (pinned cert) | `verified_official` | **Genuine** (risk 40.4) |
| WhatsApp MOD (same package, different key) | `certificate_mismatch` | **Fake** (risk 93.0) |
| Instagram, official package, not yet pinned | `unverified_no_pin` | Genuine (scored normally) |
| Unrelated third-party app | `third_party` | Genuine (scored normally) |
| "WhatsApp Plus Gold", different package | `third_party` → name-similarity rule | **Fake** (risk 83.6) |

`backend/scripts/test_apk_url_and_edge_cases.py` covers the rest with mocked network
calls (this sandbox can't reach arbitrary hosts, and a real localhost test would be
rejected by the SSRF guard itself — correctly): empty/corrupt/manifest-less APK files
all raise a clear parse error; the SSRF guard was checked directly against `8.8.8.8`/
`1.1.1.1` (allowed) and `127.0.0.1`/`10.0.0.5`/`169.254.169.254`/`0.0.0.0` (refused); a
mocked successful `.apk` download runs through identity verification correctly; a
mocked connection failure, an oversized `Content-Length`, and a server returning an
HTML error page instead of an APK all produce a clean `ApkDownloadError` / parse
error rather than a false verdict. All 7 pass. The live API was also hit directly
with `curl` against a genuinely unreachable `.apk` URL and returned
`"verdict": "Unverified"` end-to-end, not a default "Genuine".

To validate against *real* apps and real MOD APKs on your own machine: pin real
WhatsApp/Instagram fingerprints with `pin_signer.py` from your own adb-pulled APKs
(see below), then scan your own MOD APK files through Upload APK or a real `.apk`
download link.
