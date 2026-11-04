from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator


class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)
    full_name: str = Field(default="", max_length=120)


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    email: EmailStr
    full_name: str
    role: str
    is_active: bool
    created_at: datetime


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserOut


class AppInput(BaseModel):
    app_name: str = Field(min_length=1, max_length=255)
    package_name: str = Field(default="", max_length=255)
    category: str = Field(default="Productivity", max_length=64)
    description: str = Field(default="", max_length=20000)
    reviews: list[str] | str = Field(default_factory=list)
    permissions: list[str] | str = Field(default_factory=list)
    rating: float = Field(default=0.0, ge=0, le=5)
    rating_count: int = Field(default=0, ge=0)
    installs: int = Field(default=0, ge=0)
    size_mb: float = Field(default=0.0, ge=0)
    price: float = Field(default=0.0, ge=0)
    days_since_update: int = Field(default=0, ge=0)
    app_age_days: int = Field(default=0, ge=0)
    developer_app_count: int = Field(default=0, ge=0)
    has_developer_website: int = Field(default=0, ge=0, le=1)
    has_privacy_policy: int = Field(default=0, ge=0, le=1)

    @field_validator("reviews", "permissions", mode="before")
    @classmethod
    def _coerce_list(cls, v):
        if v is None:
            return []
        if isinstance(v, str):
            sep = ";" if ";" in v else "||" if "||" in v else "\n"
            return [x.strip() for x in v.split(sep) if x.strip()]
        return v


class PredictRequest(BaseModel):
    app: AppInput
    model_name: str | None = None
    save: bool = True


class BatchPredictRequest(BaseModel):
    apps: list[AppInput] = Field(min_length=1, max_length=500)
    model_name: str | None = None
    save: bool = True


class URLPredictRequest(BaseModel):
    """
    Accepts either a Play Store listing link or a plain website URL. Which pipeline
    handles it is decided server-side by inspecting the host, so the client doesn't
    need to know in advance which kind of link it is pasting.
    """
    url: str = Field(min_length=4, max_length=2048)
    save: bool = True

    @field_validator("url")
    @classmethod
    def _looks_like_url(cls, v: str) -> str:
        v = v.strip()
        if not v.lower().startswith(("http://", "https://")):
            v = f"https://{v}"
        return v


class EvidenceItem(BaseModel):
    signal: str
    detail: str
    severity: Literal["critical", "high", "medium", "low"]
    direction: Literal["risk", "trust"]
    value: float


class PredictionOut(BaseModel):
    scan_id: int | None = None
    verdict: str
    fake_probability: float
    confidence: float
    risk_score: float
    risk_band: str
    model_used: str
    model_alignment: float
    recommendation: str
    evidence: dict[str, Any]
    features: dict[str, float]
    app: dict[str, str]


class ScanOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    app_name: str
    package_name: str
    category: str
    verdict: str
    fake_probability: float
    confidence: float
    risk_score: float
    risk_band: str
    model_used: str
    recommendation: str
    source: str
    created_at: datetime


class ScanDetailOut(ScanOut):
    evidence: dict[str, Any]
    features: dict[str, float]
    model_alignment: float


class PaginatedScans(BaseModel):
    total: int
    page: int
    page_size: int
    items: list[ScanOut]


class FeedbackCreate(BaseModel):
    scan_id: int
    reported_label: Literal[0, 1]
    comment: str = Field(default="", max_length=1000)


class FeedbackOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    scan_id: int
    reported_label: int
    comment: str
    reviewed: bool
    accepted: bool | None
    created_at: datetime


class RetrainRequest(BaseModel):
    dataset_path: str | None = None
    include_feedback: bool = True
    quick: bool = False


class TrainingRunOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    triggered_by: str
    status: str
    dataset_rows: int
    best_model: str
    metrics: dict[str, Any]
    error: str
    started_at: datetime
    finished_at: datetime | None


class AnalyticsOut(BaseModel):
    total_scans: int
    fake_count: int
    genuine_count: int
    fake_rate: float
    avg_risk_score: float
    low_alignment_count: int
    by_band: dict[str, int]
    by_category: list[dict[str, Any]]
    daily: list[dict[str, Any]]
    top_signals: list[dict[str, Any]]
    recent: list[ScanOut]
