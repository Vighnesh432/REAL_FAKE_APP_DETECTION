from collections import Counter
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from ..core.database import get_db
from ..core.security import get_current_user, get_optional_user
from ..models import Feedback, Scan, User
from ..schemas import AnalyticsOut, FeedbackCreate, FeedbackOut, PaginatedScans, ScanDetailOut, ScanOut

router = APIRouter(prefix="/api", tags=["history"])


@router.get("/scans", response_model=PaginatedScans)
def list_scans(page: int = Query(1, ge=1), page_size: int = Query(20, ge=1, le=100),
               verdict: str | None = Query(None, pattern="^(Fake|Genuine)$"),
               search: str | None = None, db: Session = Depends(get_db),
               user: User = Depends(get_current_user)):
    q = db.query(Scan)
    if user.role != "admin":
        q = q.filter(Scan.user_id == user.id)
    if verdict:
        q = q.filter(Scan.verdict == verdict)
    if search:
        like = f"%{search}%"
        q = q.filter((Scan.app_name.ilike(like)) | (Scan.package_name.ilike(like)))
    total = q.count()
    items = q.order_by(Scan.created_at.desc()).offset((page - 1) * page_size).limit(page_size).all()
    return PaginatedScans(total=total, page=page, page_size=page_size,
                          items=[ScanOut.model_validate(s) for s in items])


@router.get("/scans/{scan_id}", response_model=ScanDetailOut)
def get_scan(scan_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "That scan no longer exists.")
    if user.role != "admin" and scan.user_id != user.id:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "That scan belongs to another account.")
    return ScanDetailOut.model_validate(scan)


@router.delete("/scans/{scan_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_scan(scan_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "That scan no longer exists.")
    if user.role != "admin" and scan.user_id != user.id:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "That scan belongs to another account.")
    db.delete(scan); db.commit()


@router.post("/feedback", response_model=FeedbackOut, status_code=status.HTTP_201_CREATED)
def submit_feedback(payload: FeedbackCreate, db: Session = Depends(get_db), user=Depends(get_optional_user)):
    scan = db.get(Scan, payload.scan_id)
    if not scan:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "That scan no longer exists.")
    fb = Feedback(scan_id=scan.id, user_id=user.id if user else None,
                 reported_label=payload.reported_label, comment=payload.comment)
    db.add(fb); db.commit(); db.refresh(fb)
    return fb


@router.get("/analytics", response_model=AnalyticsOut)
def analytics(days: int = Query(30, ge=1, le=365), db: Session = Depends(get_db),
             user: User = Depends(get_current_user)):
    since = datetime.now(timezone.utc) - timedelta(days=days)
    q = db.query(Scan).filter(Scan.created_at >= since)
    if user.role != "admin":
        q = q.filter(Scan.user_id == user.id)
    scans = q.all()

    total = len(scans)
    fake = sum(1 for s in scans if s.verdict == "Fake")
    by_band = Counter(s.risk_band for s in scans)
    by_cat = Counter(s.category or "Uncategorised" for s in scans)
    cat_fake = Counter((s.category or "Uncategorised") for s in scans if s.verdict == "Fake")

    daily_total, daily_fake = Counter(), Counter()
    for s in scans:
        day = s.created_at.date().isoformat()
        daily_total[day] += 1
        if s.verdict == "Fake":
            daily_fake[day] += 1

    signals = Counter()
    for s in scans:
        for item in (s.evidence or {}).get("top_reasons", []):
            if item.get("direction") == "risk":
                signals[item["signal"]] += 1

    recent = q.order_by(Scan.created_at.desc()).limit(8).all()

    return AnalyticsOut(
        total_scans=total, fake_count=fake, genuine_count=total - fake,
        fake_rate=round(fake / total, 4) if total else 0.0,
        avg_risk_score=round(sum(s.risk_score for s in scans) / total, 2) if total else 0.0,
        low_alignment_count=sum(1 for s in scans if (s.model_alignment or 1) < 0.6),
        by_band=dict(by_band),
        by_category=[{"category": c, "total": n, "fake": cat_fake.get(c, 0)} for c, n in by_cat.most_common(10)],
        daily=[{"date": d, "total": daily_total[d], "fake": daily_fake.get(d, 0)} for d in sorted(daily_total)],
        top_signals=[{"signal": s, "count": n} for s, n in signals.most_common(8)],
        recent=[ScanOut.model_validate(s) for s in recent],
    )
