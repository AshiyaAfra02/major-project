"""Pydantic request/response models for the CyberShield ML service."""
from typing import Any, Literal
from pydantic import BaseModel, ConfigDict, Field, field_validator

Severity = Literal["none", "low", "medium", "high", "critical"]
MAX_ROWS = 2000
MAX_COLUMNS = 200


class UrlRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    url: str = Field(min_length=3, max_length=2048)

    @field_validator("url")
    @classmethod
    def clean_url(cls, v: str) -> str:
        v = v.strip()
        if len(v) < 3:
            raise ValueError("url is too short")
        if any(ch.isspace() for ch in v):
            raise ValueError("url must not contain whitespace")
        return v


class TextRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    text: str = Field(min_length=1, max_length=5000)

    @field_validator("text")
    @classmethod
    def clean_text(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("text must not be empty")
        return v


class NetworkRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    rows: list[dict[str, Any]] = Field(min_length=1, max_length=MAX_ROWS)

    @field_validator("rows")
    @classmethod
    def check_rows(cls, rows):
        for i, row in enumerate(rows):
            if not row:
                raise ValueError(f"row {i} is empty")
            if len(row) > MAX_COLUMNS:
                raise ValueError(f"row {i} has more than {MAX_COLUMNS} columns")
            for key, value in row.items():
                if len(str(key)) > 100:
                    raise ValueError(f"row {i}: column name too long")
                if not isinstance(value, (int, float, str, bool, type(None))):
                    raise ValueError(f"row {i}, column '{key}': unsupported value type")
        return rows


class Prediction(BaseModel):
    label: str
    is_threat: bool
    confidence: float
    threat_score: float
    severity: Severity
    recommended_action: str
    probabilities: dict[str, float]
    reasons: list[str]
    mock: bool
    model_version: str


class NetworkRowResult(BaseModel):
    index: int
    label: str
    confidence: float
    threat_score: float
    is_threat: bool
    severity: Severity


class NetworkResponse(BaseModel):
    total_rows: int
    threats: int
    label_counts: dict[str, int]
    severity_counts: dict[str, int]
    recommended_actions: dict[str, str]
    results: list[NetworkRowResult]
    warnings: list[str]
    mock: bool
    model_version: str


class ModelStatus(BaseModel):
    loaded: bool
    mock: bool
    error: str | None = None


class HealthResponse(BaseModel):
    status: str
    mode: Literal["live", "partial", "mock"]
    models: dict[str, ModelStatus]
    versions: dict[str, str]
