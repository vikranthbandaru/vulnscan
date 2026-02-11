"""Unit tests for scanner models and core functionality."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from scanner.models import (
    CVERecord,
    Finding,
    HostResult,
    HostStatus,
    PortInfo,
    PortState,
    ScanResult,
    Severity,
    Target,
)


# ── Target Validation ─────────────────────────────────────────────────────────

class TestTarget:
    def test_valid_ipv4(self):
        t = Target(raw="192.168.1.1")
        assert t.target_type == "ipv4"

    def test_valid_cidr(self):
        t = Target(raw="10.0.0.0/24")
        assert t.target_type == "ipv4_cidr"

    def test_valid_domain(self):
        t = Target(raw="example.com")
        assert t.target_type == "domain"

    def test_valid_subdomain(self):
        t = Target(raw="mail.example.com")
        assert t.target_type == "domain"

    def test_invalid_target(self):
        with pytest.raises(Exception):
            Target(raw="not_valid!!!!")

    def test_empty_target(self):
        with pytest.raises(Exception):
            Target(raw="")

    def test_ipv4_localhost(self):
        t = Target(raw="127.0.0.1")
        assert t.target_type == "ipv4"


# ── Severity ──────────────────────────────────────────────────────────────────

class TestSeverity:
    def test_critical(self):
        assert Severity.from_cvss(9.5) == Severity.CRITICAL

    def test_high(self):
        assert Severity.from_cvss(7.5) == Severity.HIGH

    def test_medium(self):
        assert Severity.from_cvss(5.0) == Severity.MEDIUM

    def test_low(self):
        assert Severity.from_cvss(2.0) == Severity.LOW

    def test_info(self):
        assert Severity.from_cvss(0.0) == Severity.INFO

    def test_boundary_critical(self):
        assert Severity.from_cvss(9.0) == Severity.CRITICAL

    def test_boundary_high(self):
        assert Severity.from_cvss(7.0) == Severity.HIGH

    def test_boundary_medium(self):
        assert Severity.from_cvss(4.0) == Severity.MEDIUM

    def test_colors(self):
        assert Severity.CRITICAL.color == "#DC2626"
        assert Severity.HIGH.color == "#EA580C"


# ── Models ────────────────────────────────────────────────────────────────────

class TestPortInfo:
    def test_valid_port(self):
        p = PortInfo(port=80, service="http")
        assert p.port == 80
        assert p.state == PortState.OPEN

    def test_port_range(self):
        with pytest.raises(Exception):
            PortInfo(port=0)
        with pytest.raises(Exception):
            PortInfo(port=70000)


class TestCVERecord:
    def test_cvss_bounds(self):
        c = CVERecord(cve_id="CVE-2021-44228", cvss_score=10.0)
        assert c.cvss_score == 10.0

    def test_cvss_invalid(self):
        with pytest.raises(Exception):
            CVERecord(cvss_score=11.0)


class TestFinding:
    def test_finding_creation(self):
        f = Finding(
            id="CVE-2021-44228",
            title="Log4Shell",
            severity=Severity.CRITICAL,
            host="192.168.1.1",
            port=8080,
        )
        assert f.severity == Severity.CRITICAL
        assert f.host == "192.168.1.1"


# ── ScanResult Summary ───────────────────────────────────────────────────────

class TestScanResult:
    def test_compute_summary(self):
        result = ScanResult()
        host = HostResult(ip="10.0.0.1", status=HostStatus.UP, ports=[
            PortInfo(port=80, service="http"),
            PortInfo(port=443, service="https"),
        ])
        host.findings = [
            Finding(id="CVE-1", severity=Severity.CRITICAL, host="10.0.0.1"),
            Finding(id="CVE-2", severity=Severity.HIGH, host="10.0.0.1"),
            Finding(id="HDR-1", severity=Severity.MEDIUM, host="10.0.0.1"),
        ]
        result.hosts = [host]
        result.compute_summary()

        assert result.summary.total_hosts == 1
        assert result.summary.hosts_up == 1
        assert result.summary.total_ports_open == 2
        assert result.summary.total_findings == 3
        assert result.summary.critical_count == 1
        assert result.summary.high_count == 1
        assert result.summary.medium_count == 1
        assert result.summary.overall_risk_score > 0

    def test_json_serialization(self):
        result = ScanResult()
        result.hosts = [HostResult(ip="10.0.0.1", status=HostStatus.UP)]
        result.compute_summary()
        data = result.model_dump(mode="json")
        json_str = json.dumps(data, default=str)
        assert "10.0.0.1" in json_str


# ── Reporter ──────────────────────────────────────────────────────────────────

class TestReporter:
    def _make_result(self) -> ScanResult:
        result = ScanResult()
        host = HostResult(ip="10.0.0.1", status=HostStatus.UP, ports=[
            PortInfo(port=80, service="http", version="Apache 2.4.49"),
        ])
        host.findings = [
            Finding(
                id="CVE-2021-41773",
                title="Apache Path Traversal",
                severity=Severity.HIGH,
                host="10.0.0.1",
                port=80,
                service="http",
                service_version="Apache 2.4.49",
                description="Path traversal in Apache 2.4.49",
                evidence="Detected Apache 2.4.49 on 10.0.0.1:80",
                remediation="Upgrade to Apache 2.4.51+",
            ),
        ]
        result.hosts = [host]
        result.compute_summary()
        return result

    def test_json_report(self):
        from scanner.reporter import save_json
        result = self._make_result()
        with tempfile.TemporaryDirectory() as tmpdir:
            path = save_json(result, Path(tmpdir) / "test.json")
            assert path.exists()
            data = json.loads(path.read_text())
            assert data["summary"]["total_findings"] == 1

    def test_markdown_report(self):
        from scanner.reporter import save_markdown
        result = self._make_result()
        with tempfile.TemporaryDirectory() as tmpdir:
            path = save_markdown(result, Path(tmpdir) / "test.md")
            assert path.exists()
            content = path.read_text(encoding="utf-8")
            assert "CVE-2021-41773" in content
            assert "Executive Summary" in content

    def test_pdf_report(self):
        from scanner.reporter import save_pdf
        result = self._make_result()
        with tempfile.TemporaryDirectory() as tmpdir:
            path = save_pdf(result, Path(tmpdir) / "test.pdf")
            assert path.exists()
            assert path.stat().st_size > 1000  # Not an empty file
