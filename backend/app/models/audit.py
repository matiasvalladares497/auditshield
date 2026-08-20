import enum
from datetime import datetime
from sqlalchemy import String, Integer, DateTime, Boolean, Enum, ForeignKey, Text, Float, JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.core.database import Base


class AuditStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class FindingSeverity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AuditProfile(str, enum.Enum):
    BASIC = "basic"
    WEB = "web"
    INFRASTRUCTURE = "infrastructure"
    FULL = "full"
    EMAIL_DNS = "email_dns"
    OSINT_LEAK = "osint_leak"
    COMPLIANCE_CHK = "compliance_chk"
    LAN_INTERNAL = "lan_internal"
    CUSTOM = "custom"


class Audit(Base):
    __tablename__ = "audits"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    target: Mapped[str] = mapped_column(String(500), nullable=False)  # domain or IP
    target_type: Mapped[str] = mapped_column(String(50), nullable=False)  # domain, ip, cidr
    profile: Mapped[str] = mapped_column(String(50), default=AuditProfile.FULL)
    modules: Mapped[dict] = mapped_column(JSON, default={})  # which modules to run
    status: Mapped[str] = mapped_column(String(50), default=AuditStatus.PENDING)
    progress: Mapped[int] = mapped_column(Integer, default=0)  # 0-100
    current_module: Mapped[str] = mapped_column(String(100), nullable=True)
    security_score: Mapped[float] = mapped_column(Float, nullable=True)  # 0-100
    score_letter: Mapped[str] = mapped_column(String(2), nullable=True)  # A-F
    error_message: Mapped[str] = mapped_column(Text, nullable=True)
    scan_options: Mapped[dict] = mapped_column(JSON, default={})
    raw_results: Mapped[dict] = mapped_column(JSON, default={})
    summary: Mapped[dict] = mapped_column(JSON, default={})  # counts by severity

    organization_id: Mapped[int] = mapped_column(Integer, ForeignKey("organizations.id"))
    created_by: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"))
    asset_id: Mapped[int] = mapped_column(Integer, ForeignKey("assets.id"), nullable=True)

    started_at: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    organization: Mapped["Organization"] = relationship("Organization", back_populates="audits")
    created_by_user: Mapped["User"] = relationship("User", back_populates="audits")
    findings: Mapped[list["Finding"]] = relationship("Finding", back_populates="audit", cascade="all, delete-orphan")
    reports: Mapped[list["Report"]] = relationship("Report", back_populates="audit")
    asset: Mapped["Asset"] = relationship("Asset", back_populates="audits")


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    audit_id: Mapped[int] = mapped_column(Integer, ForeignKey("audits.id"), nullable=False)

    # Identification
    finding_id: Mapped[str] = mapped_column(String(50), nullable=False)  # AUDIT-2024-001
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    module: Mapped[str] = mapped_column(String(100), nullable=False)

    # CVSS
    cvss_score: Mapped[float] = mapped_column(Float, nullable=True)
    cvss_vector: Mapped[str] = mapped_column(String(200), nullable=True)
    cve_id: Mapped[str] = mapped_column(String(50), nullable=True)
    cwe_id: Mapped[str] = mapped_column(String(50), nullable=True)

    # Content
    description: Mapped[str] = mapped_column(Text, nullable=False)
    technical_details: Mapped[str] = mapped_column(Text, nullable=True)
    evidence: Mapped[str] = mapped_column(Text, nullable=True)  # HTTP response, screenshot path, etc.
    impact: Mapped[str] = mapped_column(Text, nullable=True)
    recommendation: Mapped[str] = mapped_column(Text, nullable=True)
    references: Mapped[list] = mapped_column(JSON, default=[])  # OWASP, NIST, etc.

    # Status
    is_false_positive: Mapped[bool] = mapped_column(Boolean, default=False)
    is_remediated: Mapped[bool] = mapped_column(Boolean, default=False)
    remediated_at: Mapped[datetime] = mapped_column(DateTime, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    audit: Mapped["Audit"] = relationship("Audit", back_populates="findings")


class Asset(Base):
    __tablename__ = "assets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    target: Mapped[str] = mapped_column(String(500), nullable=False)
    asset_type: Mapped[str] = mapped_column(String(50), nullable=False)  # domain, ip, cidr, url
    description: Mapped[str] = mapped_column(Text, nullable=True)
    tags: Mapped[list] = mapped_column(JSON, default=[])
    organization_id: Mapped[int] = mapped_column(Integer, ForeignKey("organizations.id"))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    last_audited: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    last_score: Mapped[float] = mapped_column(Float, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    organization: Mapped["Organization"] = relationship("Organization", back_populates="assets")
    audits: Mapped[list["Audit"]] = relationship("Audit", back_populates="asset")


class Report(Base):
    __tablename__ = "reports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    audit_id: Mapped[int] = mapped_column(Integer, ForeignKey("audits.id"))
    report_type: Mapped[str] = mapped_column(String(50), nullable=False)  # executive, technical, full
    file_path: Mapped[str] = mapped_column(String(500), nullable=True)
    file_size: Mapped[int] = mapped_column(Integer, nullable=True)
    generated_by: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    audit: Mapped["Audit"] = relationship("Audit", back_populates="reports")


# Import Organization here to avoid circular imports
from app.models.user import Organization
