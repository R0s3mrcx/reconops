from __future__ import annotations
from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime
from enum import Enum


class ScanType(str, Enum):
    quick = "quick"
    full = "full"
    stealth = "stealth"


class ScanStatus(str, Enum):
    pending = "pending"
    running = "running"
    completed = "completed"
    failed = "failed"


class ServiceCategory(str, Enum):
    standard = "standard"
    dev_exposed = "dev_exposed"
    db_exposed = "db_exposed"
    admin_panel = "admin_panel"
    legacy = "legacy"
    iot = "iot"
    high_risk = "high_risk"


class RiskLevel(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"



class ScanRequest(BaseModel):
    target: str = Field(..., examples=["127.0.0.1", "192.168.1.0/24"])
    scan_type: ScanType = ScanType.quick
    run_amass: bool = False


class FindingModel(BaseModel):
    id: str
    host: str
    port: int
    protocol: str
    service: str
    product: str
    version: str
    state: str

    risk_score: int = Field(..., ge=0, le=100)
    risk_level: RiskLevel
    category: ServiceCategory
    is_shadow: bool
    description: str
    anomaly_score: float
    feature_vector: list[float]

    discovered_at: datetime


class SeverityBreakdown(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0


class ScanSummary(BaseModel):
    target: str
    total_services: int
    shadow_count: int
    avg_risk: float
    max_risk: int
    severity: SeverityBreakdown
    categories: dict[str, int]
    scanned_at: datetime


class ScanRecord(BaseModel):
    scan_id: str
    target: str
    scan_type: ScanType
    run_amass: bool = False
    status: ScanStatus
    started_at: datetime
    completed_at: Optional[datetime] = None
    summary: Optional[ScanSummary] = None
    findings: list[FindingModel] = []
    assets: list[str] = []
    error: Optional[str] = None
