import os
import threading
from pathlib import Path

import joblib
import pandas as pd

from .explain import build_evidence, recommendation, risk_band
from .features import extract_structured
from .train import transform

ARTIFACT_PATH = Path(__file__).resolve().parents[2] / "models_store" / "model.joblib"

# Weight given to the independent rule engine when forming the final score.
# 0.0 = pure classifier, 1.0 = pure rules. The classifier is trained on synthetic
# listings and does not transfer reliably to real Play Store text on its own (the
# genuine WhatsApp listing scored ~76% fake from the classifier alone, while the rule
# engine correctly scored it 0). Blending the two is a hybrid model, consistent with
# the approach reported in the literature, and is far more robust on real inputs.
RULE_WEIGHT = float(os.getenv("RULE_WEIGHT", "0.45"))

_lock = threading.Lock()
_artifact = None


class ModelNotTrained(RuntimeError):
    pass


def load(force: bool = False):
    global _artifact
    with _lock:
        if _artifact is None or force:
            if not ARTIFACT_PATH.exists():
                raise ModelNotTrained(
                    "No trained model found. Run: python -m app.ml.train --data data/apps_dataset.csv"
                )
            _artifact = joblib.load(ARTIFACT_PATH)
    return _artifact


def is_ready() -> bool:
    return ARTIFACT_PATH.exists()


def model_info() -> dict:
    art = load()
    rep = art["report"]
    return {
        "model_name": art["model_name"],
        "version": art["version"],
        "trained_at": rep["trained_at"],
        "n_features": rep["n_features"],
        "n_samples": rep["n_samples"],
        "available_models": list(art["all_models"].keys()),
        "metrics": rep["models"][art["model_name"]],
        "all_metrics": rep["models"],
        "top_features": rep["top_features"][:15],
    }


DEFAULTS = {
    "app_name": "", "package_name": "", "category": "Productivity",
    "description": "", "reviews": "", "permissions": "",
    "rating": 0.0, "rating_count": 0, "installs": 0, "size_mb": 0.0,
    "price": 0.0, "days_since_update": 0, "app_age_days": 0,
    "developer_app_count": 0, "has_developer_website": 0, "has_privacy_policy": 0,
}


def _normalise(payload: dict) -> dict:
    row = {**DEFAULTS, **{k: v for k, v in payload.items() if v is not None}}
    if isinstance(row.get("permissions"), (list, tuple)):
        row["permissions"] = ";".join(str(p) for p in row["permissions"])
    if isinstance(row.get("reviews"), (list, tuple)):
        row["reviews"] = " || ".join(str(r) for r in row["reviews"])
    return row


def predict_one(payload: dict, model_name: str | None = None, apk_static: dict | None = None) -> dict:
    art = load()
    row = _normalise(payload)
    df = pd.DataFrame([row])

    model = art["all_models"].get(model_name) if model_name else art["model"]
    if model is None:
        raise ValueError(f"Unknown model '{model_name}'. Available: {list(art['all_models'].keys())}")
    used = model_name or art["model_name"]

    X = transform(df, art["transformers"])
    proba = float(model.predict_proba(X)[0, 1])

    features = extract_structured(row)

    meta = dict(row)
    identity_verdict = None
    if apk_static is not None:
        # An actual APK binary was analysed. Package-name matching alone is NOT
        # gatekept the way it is on the Play Store -- see app.ml.identity for why a
        # cryptographic certificate check, not a string comparison, decides trust here.
        from .identity import verify_apk_identity
        identity = verify_apk_identity(
            row.get("package_name", ""), apk_static.get("certificate_fingerprints", []),
        )
        identity_verdict = identity["identity_verdict"]
        meta["identity_verdict"] = identity_verdict
        meta["identity_claimed_brand"] = identity["claimed_brand"]
        meta["identity_matched_fingerprint"] = identity["matched_fingerprint"]

    evidence = build_evidence(features, meta)

    rule = evidence["rule_risk_score"] / 100.0
    blended = (1 - RULE_WEIGHT) * proba + RULE_WEIGHT * rule

    if identity_verdict == "certificate_mismatch":
        # Hard override, not a weighted input. A certificate mismatch on a package
        # name that claims to be a known publisher is close to a proven fact (it can
        # only happen if the file was NOT signed with that publisher's key), not a
        # probabilistic signal -- so no combination of clean-looking permissions,
        # description, or rating is allowed to pull the verdict back toward Genuine.
        # This is exactly the fingerprint a MOD APK produces: same package name,
        # different signing key.
        blended = max(blended, 0.93)
    elif identity_verdict == "verified_official":
        # Also a hard override, not gated on "no other rule fired". A cryptographic
        # signature match means this exact binary -- manifest, permissions, and all --
        # is byte-for-byte what the verified publisher shipped, so a heuristic that
        # merely THINKS a permission looks unusual or a description looks short
        # cannot be stronger evidence than the signature itself. An earlier version of
        # this gate required zero other risk signals before applying the discount,
        # which defeated the whole point in practice: real apps almost always trip at
        # least one heuristic (a blank description field, a permission our category
        # list doesn't recognise), so the certificate check was barely ever the
        # deciding factor. This is the fix.
        blended = min(blended, 0.15)

    band = risk_band(blended)
    result = {
        "verdict": "Fake" if blended >= 0.5 else "Genuine",
        "fake_probability": round(blended, 4),
        "model_probability": round(proba, 4),
        "confidence": round(abs(blended - 0.5) * 2, 4),
        "risk_score": round(blended * 100, 1),
        "risk_band": band,
        "model_used": used,
        "recommendation": recommendation(blended, evidence),
        "evidence": evidence,
        "model_alignment": round(1 - abs(blended * 100 - evidence["rule_risk_score"]) / 100, 3),
        "features": features,
        "app": {
            "app_name": row["app_name"],
            "package_name": row["package_name"],
            "category": row["category"],
        },
    }
    if identity_verdict is not None:
        result["evidence"]["identity_verdict"] = identity_verdict
        result["evidence"]["identity_claimed_brand"] = meta.get("identity_claimed_brand")
    return result


def predict_batch(payloads: list[dict], model_name: str | None = None) -> list[dict]:
    return [predict_one(p, model_name=model_name) for p in payloads]


def compare_models(payload: dict) -> dict:
    art = load()
    results = {}
    for name in art["all_models"]:
        r = predict_one(payload, model_name=name)
        results[name] = {
            "verdict": r["verdict"],
            "fake_probability": r["fake_probability"],
            "risk_band": r["risk_band"],
        }
    return {"selected_model": art["model_name"], "results": results}
