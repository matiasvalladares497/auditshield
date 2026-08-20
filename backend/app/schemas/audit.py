from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime


class AuditCreate(BaseModel):
    title: str = Field(..., min_length=3, max_length=255)
    target: str = Field(..., min_length=3, max_length=500)
    target_type: str = Field(default="domain")  # domain, ip, cidr, url
    profile: str = Field(default="full")  # basic, web, infrastructure, full, custom
    modules: Dict[str, bool] = Field(default={
        "osint": True,
        "port_scan": True,
        "ssl": True,
        "web": True,
        "dns": True,
        "email_security": True,
        "info_exposure": True,
        "cve_matching": True,
        "waf_detection": True,
        "compliance": True,
    })
    scan_options: Dict[str, Any] = Field(default={
        "intensity": "normal",  # stealth, normal, aggressive
        "port_range": "1-1000",
        "timeout": 30,
    })
    asset_id: Optional[int] = None


class AuditUpdate(BaseModel):
    title: Optional[str] = None
    status: Optional[str] = None


class FindingResponse(BaseModel):
    id: int
    finding_id: str
    title: str
    severity: str
    module: str
    cvss_score: Optional[float]
    cvss_vector: Optional[str]
    cve_id: Optional[str]
    cwe_id: Optional[str]
    description: str
    technical_details: Optional[str]
    evidence: Optional[str]
    impact: Optional[str]
    recommendation: Optional[str]
    references: List[str]
    is_false_positive: bool
    is_remediated: bool
    remediated_at: Optional[datetime]
    created_at: datetime

    class Config:
        from_attributes = True


class AuditResponse(BaseModel):
    id: int
    title: str
    target: str
    target_type: str
    profile: str
    modules: Dict
    status: str
    progress: int
    current_module: Optional[str]
    security_score: Optional[float]
    score_letter: Optional[str]
    error_message: Optional[str]
    summary: Dict
    organization_id: int
    created_by: int
    asset_id: Optional[int]
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    created_at: datetime
    findings: Optional[List[FindingResponse]] = None

    class Config:
        from_attributes = True


class AuditListResponse(BaseModel):
    id: int
    title: str
    target: str
    status: str
    progress: int
    security_score: Optional[float]
    score_letter: Optional[str]
    summary: Dict
    created_at: datetime
    completed_at: Optional[datetime]

    class Config:
        from_attributes = True


class FindingUpdate(BaseModel):
    is_false_positive: Optional[bool] = None
    is_remediated: Optional[bool] = None


class AssetCreate(BaseModel):
    name: str = Field(..., min_length=2, max_length=255)
    target: str = Field(..., min_length=3, max_length=500)
    asset_type: str = Field(default="domain")
    description: Optional[str] = None
    tags: List[str] = []


class AssetResponse(BaseModel):
    id: int
    name: str
    target: str
    asset_type: str
    description: Optional[str]
    tags: List[str]
    organization_id: int
    is_active: bool
    last_audited: Optional[datetime]
    last_score: Optional[float]
    created_at: datetime

    class Config:
        from_attributes = True


class ReportCreate(BaseModel):
    audit_id: int
    report_type: str = Field(default="full")  # executive, technical, full


class ReportResponse(BaseModel):
    id: int
    audit_id: int
    report_type: str
    file_path: Optional[str]
    file_size: Optional[int]
    generated_by: int
    created_at: datetime

    class Config:
        from_attributes = True
