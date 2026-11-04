import io

import pandas as pd
from fastapi import (
    APIRouter, Depends, File, Form, HTTPException, Response, UploadFile, status,
)
from sqlalchemy.orm import Session

from ..core.config import settings
from ..core.database import get_db
from ..core.security import get_current_user, get_optional_user
from ..ml import predict as ml
from ..ml import website_check
from ..ml.apk import ApkParseError, analyse_apk
from ..ml.apk_download import ApkDownloadError, fetch_apk_bytes, looks_like_apk_url
from ..ml.play_store import PlayStoreError, fetch_app_input, is_play_store_url
from ..ml.report import build_report
from ..models import Scan
from ..schemas import (
    AppInput, BatchPredictRequest, PredictionOut, PredictRequest, URLPredictRequest,
)

router = APIRouter(prefix="/api", tags=["prediction"])


def _guard_model_ready():
    if not ml.is_ready():
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "No trained model is loaded. An administrator needs to run training first.",
        )


def _persist(db: Session, result: dict, payload: dict, user, source: str) -> Scan:
    scan = Scan(
        user_id=user.id if user else None,
        app_name=result["app"]["app_name"],
        package_name=result["app"]["package_name"],
        category=result["app"]["category"],
        verdict=result["verdict"],
        fake_probability=result["fake_probability"],
        confidence=result["confidence"],
        risk_score=result["risk_score"],
        risk_band=result["risk_band"],
        model_used=result["model_used"],
        model_alignment=result["model_alignment"],
        recommendation=result["recommendation"],
        evidence=result["evidence"],
        features=result["features"],
        raw_input=payload,
        source=source,
    )
    db.add(scan)
    return scan


@router.post("/predict", response_model=PredictionOut)
def predict(req: PredictRequest, db: Session = Depends(get_db), user=Depends(get_optional_user)):
    _guard_model_ready()
    payload = req.app.model_dump()
    try:
        result = ml.predict_one(payload, model_name=req.model_name)
    except ValueError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e))

    scan_id = None
    if req.save:
        scan = _persist(db, result, payload, user, "manual")
        db.commit()
        db.refresh(scan)
        scan_id = scan.id
    return PredictionOut(scan_id=scan_id, **result)


@router.post("/predict/batch", response_model=list[PredictionOut])
def predict_batch(req: BatchPredictRequest, db: Session = Depends(get_db),
                  user=Depends(get_optional_user)):
    _guard_model_ready()
    payloads = [a.model_dump() for a in req.apps]
    results = ml.predict_batch(payloads, model_name=req.model_name)

    out = []
    for payload, result in zip(payloads, results):
        scan_id = None
        if req.save:
            scan = _persist(db, result, payload, user, "batch")
            db.flush()
            scan_id = scan.id
        out.append(PredictionOut(scan_id=scan_id, **result))
    if req.save:
        db.commit()
    return out


CSV_ALIASES = {
    "app": "app_name", "name": "app_name", "title": "app_name",
    "package": "package_name", "pkg": "package_name",
    "desc": "description", "summary": "description",
    "review": "reviews", "user_reviews": "reviews",
    "perms": "permissions", "permission": "permissions",
    "score": "rating", "stars": "rating",
    "reviews_count": "rating_count", "num_ratings": "rating_count",
    "downloads": "installs", "install_count": "installs",
    "size": "size_mb", "genre": "category",
}


@router.post("/predict/upload", response_model=list[PredictionOut])
async def predict_from_csv(file: UploadFile = File(...), db: Session = Depends(get_db),
                           user=Depends(get_optional_user)):
    _guard_model_ready()
    if not file.filename.lower().endswith(".csv"):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Upload a .csv file.")

    raw = await file.read()
    try:
        df = pd.read_csv(io.BytesIO(raw))
    except Exception:
        raise HTTPException(status.HTTP_400_BAD_REQUEST,
                            "That file could not be read as CSV. Check the delimiter and encoding.")

    df.columns = [CSV_ALIASES.get(c.strip().lower(), c.strip().lower()) for c in df.columns]
    if "app_name" not in df.columns:
        raise HTTPException(status.HTTP_400_BAD_REQUEST,
                            "The CSV needs an 'app_name' column (or 'app', 'name', 'title').")
    if len(df) > settings.MAX_BATCH_SIZE:
        raise HTTPException(
            status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            f"That file has {len(df)} rows. Split it into batches of {settings.MAX_BATCH_SIZE} or fewer.")

    apps = []
    for rec in df.fillna("").to_dict("records"):
        clean = {k: v for k, v in rec.items() if k in AppInput.model_fields}
        for num in ("rating", "rating_count", "installs", "size_mb", "price",
                    "days_since_update", "app_age_days", "developer_app_count",
                    "has_developer_website", "has_privacy_policy"):
            if clean.get(num) in ("", None):
                clean[num] = 0
        try:
            apps.append(AppInput(**clean))
        except Exception:
            continue

    if not apps:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "No valid rows were found in that file.")
    return predict_batch(BatchPredictRequest(apps=apps, save=True), db=db, user=user)


@router.post("/predict/apk", response_model=PredictionOut)
async def predict_from_apk(
    file: UploadFile = File(...), app_name: str = Form(""), category: str = Form("Productivity"),
    description: str = Form(""), rating: float = Form(0.0), rating_count: int = Form(0),
    installs: int = Form(0), db: Session = Depends(get_db), user=Depends(get_optional_user),
):
    _guard_model_ready()
    if not file.filename.lower().endswith(".apk"):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Upload a .apk file.")

    raw = await file.read()
    if len(raw) > 150 * 1024 * 1024:
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                            "That APK is larger than the 150 MB limit.")
    try:
        static = analyse_apk(raw)
    except ApkParseError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e))

    payload = {
        "app_name": app_name or static["package_name"].split(".")[-1] or file.filename[:-4],
        "package_name": static["package_name"], "category": category, "description": description,
        "reviews": [], "permissions": static["permissions"],
        # Rating / review count / install count are NOT verified marketplace data on
        # this path -- they are free-text fields anyone uploading an APK can type by
        # hand (see frontend Scan.jsx). Feeding them into the model as if they were
        # fetched from a real listing would let a MOD APK's uploader manufacture
        # "4.8 stars, 500M installs" for a binary that has never been on any store.
        # Only /predict/url's Play Store fetch path gets to use real numbers here; a
        # raw upload gets none, so explain.py's "no marketplace listing data" guard
        # applies honestly instead of trust being manufactured from unverified input.
        "rating": 0.0, "rating_count": 0, "installs": 0,
        "size_mb": static["size_mb"],
        "price": 0.0, "days_since_update": 0, "app_age_days": 0, "developer_app_count": 0,
        "has_developer_website": 0, "has_privacy_policy": 0,
    }
    result = ml.predict_one(payload, apk_static=static)
    result["evidence"]["static_analysis"] = static
    if rating or rating_count or installs:
        result["evidence"]["user_claimed_metadata"] = {
            "rating": rating, "rating_count": rating_count, "installs": installs,
            "note": "Entered by the person uploading this file. Not verified against "
                    "any marketplace and excluded from the score.",
        }
    if not static["is_signed"]:
        result["evidence"]["grouped"].setdefault("package", []).append({
            "signal": "Package is not signed",
            "detail": "No signing certificate was found. Android requires a valid signature, "
                     "so this file has been modified after signing or was never published.",
            "severity": "critical", "direction": "risk", "value": 0.0,
        })

    scan = _persist(db, result, payload, user, "apk")
    db.commit()
    db.refresh(scan)
    return PredictionOut(scan_id=scan.id, **result)


def _unverified_apk_result(url: str, reason: str) -> dict:
    """Used when a direct .apk link couldn't be downloaded or didn't parse as a valid
    APK. This is a THIRD verdict, not a fallback to Genuine or Fake -- the whole point
    of point 4 in the architecture spec is that "we couldn't check" must never be
    reported as "it's fine". risk_score sits at the exact midpoint (50) so it doesn't
    lean either way, and risk_band naturally falls out as 'Moderate' from the same
    thresholds every other scan uses -- no separate banding logic to keep in sync."""
    from ..ml.explain import risk_band
    return {
        "verdict": "Unverified",
        "fake_probability": 0.5,
        "model_probability": 0.5,
        "confidence": 0.0,
        "risk_score": 50.0,
        "risk_band": risk_band(0.5),
        "model_used": "none",
        "recommendation": (
            f"This APK could not be retrieved or verified ({reason}). This is not a "
            "safety judgment in either direction -- download the file yourself and "
            "use Upload APK instead, or verify the source through another channel."
        ),
        "evidence": {
            "grouped": {}, "rule_risk_score": 0.0, "risk_signal_count": 0, "trust_signal_count": 0,
            "top_reasons": [{
                "signal": "Could not verify this APK", "detail": reason,
                "severity": "medium", "direction": "risk", "value": 0.0,
            }],
            "identity_verdict": "download_failed",
        },
        "model_alignment": 0.0,
        "features": {},
        "app": {"app_name": url.rsplit("/", 1)[-1] or "unknown.apk", "package_name": "", "category": ""},
    }


@router.post("/predict/url", response_model=PredictionOut)
def predict_from_url(req: URLPredictRequest, db: Session = Depends(get_db),
                     user=Depends(get_optional_user)):
    """
    Scans a pasted link, one of three ways depending on what the link actually is:

    - A Play Store *listing* link is fetched and run through the full ML + rule
      pipeline exactly like a manual entry, using the real listing data instead of
      anything the user typed in.
    - A direct .apk *download* link is fetched and the downloaded BINARY is run
      through the same identity-verification + ML/rule pipeline as an uploaded file
      (routers/predict.py::predict_from_apk) -- a listing scrape tells you nothing
      about the bytes actually served at that link. If the download fails, times
      out, or isn't a valid APK, the result is an explicit "Unverified" verdict, not
      a default to Genuine.
    - Anything else is treated as a website and checked with a separate set of
      phishing-style heuristics — the trained classifier is fitted on app metadata
      and would produce a meaningless number for a page with no permissions,
      installs, or app-store rating at all.
    """
    url = req.url

    if is_play_store_url(url):
        _guard_model_ready()
        try:
            payload = fetch_app_input(url)
        except PlayStoreError as e:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e))
        source_meta = payload.pop("_source", {})
        try:
            result = ml.predict_one(payload)
        except ValueError as e:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e))
        result["evidence"]["fetched_from"] = {"type": "play_store", "url": url, **source_meta}
        source = "play_store_url"

    elif looks_like_apk_url(url):
        _guard_model_ready()
        try:
            apk_bytes, fetch_meta = fetch_apk_bytes(url)
            static = analyse_apk(apk_bytes)
        except (ApkDownloadError, ApkParseError) as e:
            result = _unverified_apk_result(url, str(e))
            payload = {"url": url}
            source = "apk_url_failed"
        else:
            payload = {
                "app_name": static["package_name"].split(".")[-1] or url.rsplit("/", 1)[-1],
                "package_name": static["package_name"], "category": "Productivity", "description": "",
                "reviews": [], "permissions": static["permissions"],
                # Same reasoning as the Upload-APK route: nothing here is verified
                # marketplace data, so it must not be fabricated from the URL.
                "rating": 0.0, "rating_count": 0, "installs": 0, "size_mb": static["size_mb"],
                "price": 0.0, "days_since_update": 0, "app_age_days": 0, "developer_app_count": 0,
                "has_developer_website": 0, "has_privacy_policy": 0,
            }
            result = ml.predict_one(payload, apk_static=static)
            result["evidence"]["static_analysis"] = static
            result["evidence"]["fetched_from"] = {"type": "apk_download", "url": url, **fetch_meta}
            source = "apk_download_url"

    else:
        try:
            result = website_check.analyse_url(url)
        except website_check.FetchError as e:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e))
        payload = {"url": url}
        source = "website_url"

    scan_id = None
    if req.save:
        scan = _persist(db, result, payload, user, source)
        db.commit()
        db.refresh(scan)
        scan_id = scan.id
    return PredictionOut(scan_id=scan_id, **result)


@router.get("/scans/{scan_id}/report.pdf")
def download_report(scan_id: int, db: Session = Depends(get_db), user=Depends(get_current_user)):
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "That scan no longer exists.")
    if user.role != "admin" and scan.user_id != user.id:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "That scan belongs to another account.")

    pdf = build_report({
        "scan_id": scan.id, "verdict": scan.verdict, "fake_probability": scan.fake_probability,
        "confidence": scan.confidence, "risk_score": scan.risk_score, "risk_band": scan.risk_band,
        "model_used": scan.model_used, "model_alignment": scan.model_alignment,
        "recommendation": scan.recommendation, "evidence": scan.evidence or {},
        "app": {"app_name": scan.app_name, "package_name": scan.package_name, "category": scan.category},
    })
    safe = "".join(c for c in scan.app_name if c.isalnum() or c in " -_").strip() or "app"
    return Response(content=pdf, media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="security-report-{safe}.pdf"'})


@router.post("/predict/compare")
def compare(app: AppInput):
    _guard_model_ready()
    return ml.compare_models(app.model_dump())


@router.get("/model/info")
def model_info():
    _guard_model_ready()
    return ml.model_info()
