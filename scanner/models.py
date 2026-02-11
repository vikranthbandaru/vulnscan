"""
Pydantic v2 data models for the vulnerability scanner.

Defines the complete data hierarchy: Target → HostResult → PortInfo → Finding → CVERecord,
plus ScanConfig for runtime options and ScanResult as the top-level report envelope.
"""

from __future__ import annotations

import enum
import ipaddress
import re
from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field, field_validator


# ── Enumerations ──────────────────────────────────────────────────────────────

class Severity(str, enum.Enum):
    """Risk severity levels aligned with CVSS v3 scoring."""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"

    @classmethod
    def from_cvss(cls, score: float) -> "Severity":
        if score >= 9.0:
            return cls.CRITICAL
        elif score >= 7.0:
            return cls.HIGH
        elif score >= 4.0:
            return cls.MEDIUM
        elif score > 0.0:
            return cls.LOW
        return cls.INFO

    @property
    def color(self) -> str:
        return {
            "Critical": "#DC2626",
            "High": "#EA580C",
            "Medium": "#D97706",
            "Low": "#2563EB",
            "Info": "#6B7280",
        }[self.value]

    @property
    def rich_color(self) -> str:
        return {
            "Critical": "bold red",
            "High": "dark_orange",
            "Medium": "yellow",
            "Low": "blue",
            "Info": "dim",
        }[self.value]


class HostStatus(str, enum.Enum):
    UP = "up"
    DOWN = "down"
    UNKNOWN = "unknown"


class PortState(str, enum.Enum):
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"


# ── Core Models ───────────────────────────────────────────────────────────────

class Target(BaseModel):
    """Validated scan target — single IP, CIDR range, or domain name."""
    raw: str
    target_type: str = ""  # "ipv4", "ipv4_cidr", "domain"

    @field_validator("raw")
    @classmethod
    def validate_raw(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("Target cannot be empty")
        return v

    def model_post_init(self, __context: Any) -> None:
        if not self.target_type:
            self.target_type = self._detect_type()

    def _detect_type(self) -> str:
        raw = self.raw
        # CIDR
        if "/" in raw:
            try:
                ipaddress.ip_network(raw, strict=False)
                return "ipv4_cidr"
            except ValueError:
                pass
        # Plain IP
        try:
            ipaddress.ip_address(raw)
            return "ipv4"
        except ValueError:
            pass
        # Domain
        domain_re = re.compile(
            r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,}$"
        )
        if domain_re.match(raw):
            return "domain"
        raise ValueError(f"Invalid target: {raw!r}. Must be IPv4, CIDR, or domain.")


class PortInfo(BaseModel):
    """Information about a single discovered port."""
    port: int = Field(ge=1, le=65535)
    protocol: str = "tcp"
    state: PortState = PortState.OPEN
    service: str = ""
    version: str = ""
    banner: str = ""
    cpe: str = ""


class CVERecord(BaseModel):
    """A single CVE entry associated with a service/version."""
    cve_id: str = ""
    cvss_score: float = Field(default=0.0, ge=0.0, le=10.0)
    cvss_vector: str = ""
    severity: Severity = Severity.INFO
    description: str = ""
    references: list[str] = Field(default_factory=list)
    exploit_available: bool = False
    published: str = ""


class Finding(BaseModel):
    """A single vulnerability finding with evidence and remediation."""
    id: str = ""
    title: str = ""
    severity: Severity = Severity.INFO
    host: str = ""
    port: Optional[int] = None
    service: str = ""
    service_version: str = ""
    cve: Optional[CVERecord] = None
    description: str = ""
    evidence: str = ""
    remediation: str = ""
    timestamp: str = Field(default_factory=lambda: datetime.now().isoformat())

    @property
    def cvss_score(self) -> float:
        return self.cve.cvss_score if self.cve else 0.0


class HostResult(BaseModel):
    """Aggregated scan results for a single host."""
    ip: str = ""
    hostname: str = ""
    status: HostStatus = HostStatus.UNKNOWN
    response_time_ms: float = 0.0
    os_guess: str = ""
    ports: list[PortInfo] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)


class ScanMetadata(BaseModel):
    """Metadata about the scan run."""
    scanner_version: str = "1.0.0"
    scan_start: str = Field(default_factory=lambda: datetime.now().isoformat())
    scan_end: str = ""
    targets_requested: list[str] = Field(default_factory=list)
    ports_scanned: str = ""
    cvss_threshold: float = 4.0
    nmap_version: str = ""
    authorization_confirmed: bool = False


class ScanSummary(BaseModel):
    """High-level summary statistics for the report."""
    total_hosts: int = 0
    hosts_up: int = 0
    total_ports_open: int = 0
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    overall_risk_score: float = 0.0


class ScanResult(BaseModel):
    """Top-level scan result envelope — serialized as the JSON report."""
    metadata: ScanMetadata = Field(default_factory=ScanMetadata)
    summary: ScanSummary = Field(default_factory=ScanSummary)
    hosts: list[HostResult] = Field(default_factory=list)

    def compute_summary(self) -> None:
        """Recompute summary stats from host data."""
        s = self.summary
        s.total_hosts = len(self.hosts)
        s.hosts_up = sum(1 for h in self.hosts if h.status == HostStatus.UP)
        s.total_ports_open = sum(
            sum(1 for p in h.ports if p.state == PortState.OPEN)
            for h in self.hosts
        )
        all_findings = [f for h in self.hosts for f in h.findings]
        s.total_findings = len(all_findings)
        s.critical_count = sum(1 for f in all_findings if f.severity == Severity.CRITICAL)
        s.high_count = sum(1 for f in all_findings if f.severity == Severity.HIGH)
        s.medium_count = sum(1 for f in all_findings if f.severity == Severity.MEDIUM)
        s.low_count = sum(1 for f in all_findings if f.severity == Severity.LOW)
        s.info_count = sum(1 for f in all_findings if f.severity == Severity.INFO)

        # Weighted risk score (0-10)
        weights = {Severity.CRITICAL: 10, Severity.HIGH: 7.5, Severity.MEDIUM: 5,
                   Severity.LOW: 2.5, Severity.INFO: 0.5}
        if all_findings:
            total_weight = sum(weights.get(f.severity, 0) for f in all_findings)
            s.overall_risk_score = round(min(total_weight / len(all_findings), 10.0), 1)
        else:
            s.overall_risk_score = 0.0
