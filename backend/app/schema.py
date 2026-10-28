"""Shared Finding record (PRD §7). Every layer reads or writes this. Do not change without asking."""
from typing import Literal

from pydantic import BaseModel, Field

ConfidenceTier = Literal["pattern-match", "reachable", "proof-confirmed"]
Status = Literal["open", "fixed", "accepted"]
DetectedAt = Literal["write", "review", "watch"]


class Finding(BaseModel):
    id: str
    scan_id: str
    file: str
    line: int
    cwe: str
    owasp: str = ""
    source: str = ""
    sink: str
    path: list[str] = Field(default_factory=list)
    detector: str
    ml_rank: float = 0.0
    severity: float = 0.0
    severity_factors: dict[str, float] = Field(default_factory=dict)
    confidence_tier: ConfidenceTier = "pattern-match"
    fix_suggestion: str = ""
    status: Status = "open"
    introduced_in: str = ""
    detected_at: DetectedAt = "review"
    time_to_detect: float = 0
