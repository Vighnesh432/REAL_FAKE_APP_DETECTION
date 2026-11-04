from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from ..core.config import settings
from ..core.database import SessionLocal, get_db
from ..core.security import require_admin
from ..ml import predict as ml
from ..models import Feedback, Scan, TrainingRun, User
from ..schemas import FeedbackOut, RetrainRequest, TrainingRunOut, UserOut

router = APIRouter(prefix="/api/admin", tags=["admin"])


def _merge_feedback(base_path: str) -> tuple[str, int]:
    base = pd.read_csv(base_path)
    db = SessionLocal()
    try:
        rows = (db.query(Feedback, Scan).join(Scan, Feedback.scan_id == Scan.id)
               .filter(Feedback.reviewed.is_(True), Feedback.accepted.is_(True)).all())
        extra = []
        for fb, scan in rows:
            raw = scan.raw_input or {}
            extra.append({
                "app_id": f"FB{fb.id:06d}", "app_name": raw.get("app_name", scan.app_name),
                "package_name": raw.get("package_name", scan.package_name),
                "category": raw.get("category", scan.category),
                "description": raw.get("description", ""),
                "reviews": " || ".join(raw.get("reviews", [])) if isinstance(raw.get("reviews"), list) else raw.get("reviews", ""),
                "permissions": ";".join(raw.get("permissions", [])) if isinstance(raw.get("permissions"), list) else raw.get("permissions", ""),
                "rating": raw.get("rating", 0), "rating_count": raw.get("rating_count", 0),
                "installs": raw.get("installs", 0), "size_mb": raw.get("size_mb", 0),
                "price": raw.get("price", 0), "days_since_update": raw.get("days_since_update", 0),
                "app_age_days": raw.get("app_age_days", 0),
                "developer_app_count": raw.get("developer_app_count", 0),
                "has_developer_website": raw.get("has_developer_website", 0),
                "has_privacy_policy": raw.get("has_privacy_policy", 0),
                "content_rating": "Everyone", "label": fb.reported_label,
            })
    finally:
        db.close()
    if not extra:
        return base_path, 0
    merged = pd.concat([base, pd.DataFrame(extra)], ignore_index=True)
    out = str(Path(base_path).with_name("apps_dataset_with_feedback.csv"))
    merged.to_csv(out, index=False)
    return out, len(extra)


def _run_training(run_id: int, dataset_path: str, include_feedback: bool, quick: bool):
    from ..ml.train import run as train_run
    db = SessionLocal()
    run = None
    try:
        run = db.get(TrainingRun, run_id)
        added, path = 0, dataset_path
        if include_feedback:
            path, added = _merge_feedback(dataset_path)
        report = train_run(path, quick=quick)
        ml.load(force=True)
        run.status = "success"; run.dataset_rows = report["n_samples"]
        run.best_model = report["best_model"]
        run.metrics = {"models": report["models"], "feedback_rows_added": added,
                      "n_features": report["n_features"]}
    except Exception as e:
        if run:
            run.status = "failed"; run.error = f"{type(e).__name__}: {e}"
    finally:
        if run:
            run.finished_at = datetime.now(timezone.utc); db.commit()
        db.close()


@router.post("/retrain", response_model=TrainingRunOut, status_code=status.HTTP_202_ACCEPTED)
def retrain(req: RetrainRequest, background: BackgroundTasks, db: Session = Depends(get_db),
           admin: User = Depends(require_admin)):
    if db.query(TrainingRun).filter(TrainingRun.status == "running").first():
        raise HTTPException(status.HTTP_409_CONFLICT, "A training run is already in progress.")
    dataset = req.dataset_path or settings.DATASET_PATH
    if not Path(dataset).exists():
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"Dataset not found at {dataset}.")
    run = TrainingRun(triggered_by=admin.email, status="running")
    db.add(run); db.commit(); db.refresh(run)
    background.add_task(_run_training, run.id, dataset, req.include_feedback, req.quick)
    return run


@router.get("/training-runs", response_model=list[TrainingRunOut])
def training_runs(limit: int = Query(20, ge=1, le=100), db: Session = Depends(get_db),
                  admin: User = Depends(require_admin)):
    return db.query(TrainingRun).order_by(TrainingRun.started_at.desc()).limit(limit).all()


@router.get("/feedback", response_model=list[FeedbackOut])
def list_feedback(reviewed: bool | None = None, limit: int = Query(50, ge=1, le=200),
                  db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    q = db.query(Feedback)
    if reviewed is not None:
        q = q.filter(Feedback.reviewed.is_(reviewed))
    return q.order_by(Feedback.created_at.desc()).limit(limit).all()


@router.patch("/feedback/{feedback_id}", response_model=FeedbackOut)
def review_feedback(feedback_id: int, accepted: bool, db: Session = Depends(get_db),
                    admin: User = Depends(require_admin)):
    fb = db.get(Feedback, feedback_id)
    if not fb:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "That feedback entry no longer exists.")
    fb.reviewed = True; fb.accepted = accepted
    db.commit(); db.refresh(fb)
    return fb


@router.get("/users", response_model=list[UserOut])
def list_users(db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    return db.query(User).order_by(User.created_at.desc()).all()


@router.patch("/users/{user_id}/status", response_model=UserOut)
def set_user_status(user_id: int, is_active: bool, db: Session = Depends(get_db),
                    admin: User = Depends(require_admin)):
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "That account no longer exists.")
    if user.id == admin.id:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "You cannot disable your own account.")
    user.is_active = is_active
    db.commit(); db.refresh(user)
    return user


@router.get("/stats")
def system_stats(db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    return {
        "users": db.query(User).count(),
        "active_users": db.query(User).filter(User.is_active.is_(True)).count(),
        "scans": db.query(Scan).count(),
        "fake_scans": db.query(Scan).filter(Scan.verdict == "Fake").count(),
        "pending_feedback": db.query(Feedback).filter(Feedback.reviewed.is_(False)).count(),
        "training_runs": db.query(TrainingRun).count(),
        "model": ml.model_info() if ml.is_ready() else None,
    }
