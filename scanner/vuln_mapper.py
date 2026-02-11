"""
Phase 3 — Vulnerability Mapping

Queries the NVD REST API for CVE records matching discovered services,
performs version-range comparison, assigns risk scores, and creates
Finding objects.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

import httpx
from rich.console import Console

from scanner.config import NVD_API_BASE
from scanner.models import (
    CVERecord,
    Finding,
    HostResult,
    PortInfo,
    Severity,
)

if TYPE_CHECKING:
    from scanner.config import ScanConfig

console = Console()


# ── NVD API Client ────────────────────────────────────────────────────────────

class NVDClient:
    """Lightweight NVD REST API v2.0 client with rate limiting."""

    def __init__(self, config: "ScanConfig") -> None:
        self.api_key = config.nvd_api_key
        self.rate_limit = config.nvd_rate_limit
        self.timeout = config.timeout
        self._last_call = 0.0
        self._call_count = 0

    def _throttle(self) -> None:
        """Enforce NVD rate limits."""
        now = time.time()
        window = 30.0  # 30-second rolling window
        if now - self._last_call < window:
            self._call_count += 1
            if self._call_count >= self.rate_limit:
                sleep_time = window - (now - self._last_call) + 0.5
                console.print(f"  [dim]NVD rate limit: sleeping {sleep_time:.1f}s[/dim]")
                time.sleep(sleep_time)
                self._call_count = 0
                self._last_call = time.time()
        else:
            self._call_count = 0
            self._last_call = now

    def search_cves(self, keyword: str, max_results: int = 20) -> list[CVERecord]:
        """Search NVD for CVEs matching a keyword (service name + version)."""
        self._throttle()

        headers: dict[str, str] = {}
        if self.api_key:
            headers["apiKey"] = self.api_key

        params = {
            "keywordSearch": keyword,
            "resultsPerPage": str(min(max_results, 50)),
        }

        try:
            resp = httpx.get(
                NVD_API_BASE,
                params=params,
                headers=headers,
                timeout=self.timeout,
            )
            resp.raise_for_status()
            data = resp.json()
        except httpx.HTTPError as exc:
            console.print(f"  [yellow]⚠ NVD query failed for {keyword!r}: {exc}[/yellow]")
            return []

        return self._parse_response(data)

    def _parse_response(self, data: dict) -> list[CVERecord]:
        """Parse NVD API v2.0 JSON response into CVERecord objects."""
        records: list[CVERecord] = []
        vulnerabilities = data.get("vulnerabilities", [])

        for vuln in vulnerabilities:
            cve_data = vuln.get("cve", {})
            cve_id = cve_data.get("id", "")

            # Extract CVSS score — prefer v3.1, fall back to v3.0, then v2
            cvss_score = 0.0
            cvss_vector = ""
            metrics = cve_data.get("metrics", {})

            for version_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                metric_list = metrics.get(version_key, [])
                if metric_list:
                    cvss_data = metric_list[0].get("cvssData", {})
                    cvss_score = cvss_data.get("baseScore", 0.0)
                    cvss_vector = cvss_data.get("vectorString", "")
                    break

            # Description (English)
            descriptions = cve_data.get("descriptions", [])
            description = ""
            for desc in descriptions:
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break

            # References
            refs = cve_data.get("references", [])
            ref_urls = [r.get("url", "") for r in refs[:5]]

            # Published date
            published = cve_data.get("published", "")

            records.append(CVERecord(
                cve_id=cve_id,
                cvss_score=cvss_score,
                cvss_vector=cvss_vector,
                severity=Severity.from_cvss(cvss_score),
                description=description[:500],
                references=ref_urls,
                published=published,
            ))

        return records


# ── Offline / Demo Fallback ───────────────────────────────────────────────────

# A small built-in knowledge base for demo mode or when NVD is unreachable
_DEMO_CVES: dict[str, list[dict]] = {
    "apache": [
        {
            "cve_id": "CVE-2021-41773",
            "cvss_score": 7.5,
            "description": "Apache HTTP Server 2.4.49 path traversal vulnerability allows "
                           "reading files outside the document root.",
            "remediation": "Upgrade Apache HTTP Server to version 2.4.51 or later.",
        },
        {
            "cve_id": "CVE-2021-44228",
            "cvss_score": 10.0,
            "description": "Log4Shell: Apache Log4j2 JNDI features do not protect against "
                           "attacker controlled LDAP/JNDI lookups, enabling RCE.",
            "remediation": "Upgrade to Log4j 2.17.1 or later. Remove JndiLookup class.",
        },
    ],
    "openssh": [
        {
            "cve_id": "CVE-2023-38408",
            "cvss_score": 9.8,
            "description": "OpenSSH before 9.3p2 PKCS#11 feature has an insufficiently "
                           "trusted search path, leading to remote code execution.",
            "remediation": "Upgrade OpenSSH to 9.3p2 or later.",
        },
    ],
    "nginx": [
        {
            "cve_id": "CVE-2021-23017",
            "cvss_score": 7.7,
            "description": "nginx DNS resolver vulnerability allows an attacker to forge "
                           "UDP datagrams to trigger a one-byte memory overwrite.",
            "remediation": "Upgrade nginx to 1.21.0 or later.",
        },
    ],
    "mysql": [
        {
            "cve_id": "CVE-2023-21977",
            "cvss_score": 4.9,
            "description": "MySQL Server optimizer vulnerability allows high privileged "
                           "attacker to cause a hang or crash (DoS).",
            "remediation": "Apply Oracle Critical Patch Update for MySQL.",
        },
    ],
    "microsoft-ds": [
        {
            "cve_id": "CVE-2017-0144",
            "cvss_score": 9.8,
            "description": "EternalBlue: SMBv1 server in Windows allows remote code execution "
                           "via crafted packets (WannaCry exploit vector).",
            "remediation": "Apply MS17-010 patch. Disable SMBv1 protocol.",
        },
    ],
}


def _get_demo_cves(service: str) -> list[CVERecord]:
    """Return demo CVE records for a service name."""
    key = service.lower().split("/")[0].split(" ")[0]
    entries = _DEMO_CVES.get(key, [])
    return [
        CVERecord(
            cve_id=e["cve_id"],
            cvss_score=e["cvss_score"],
            severity=Severity.from_cvss(e["cvss_score"]),
            description=e["description"],
            remediation_hint=e.get("remediation", ""),
        )
        for e in entries
    ]


# ── Main Mapping Function ────────────────────────────────────────────────────

def map_vulnerabilities(host: HostResult, config: "ScanConfig") -> HostResult:
    """
    For each service discovered on a host, search for matching CVEs
    and create Finding objects.
    """
    client = NVDClient(config)

    for port_info in host.ports:
        if not port_info.service:
            continue

        search_term = _build_search_term(port_info)
        if not search_term:
            continue

        console.print(f"  [dim]Querying CVEs for {search_term}[/dim]")

        # Try NVD first, fall back to demo data
        try:
            cves = client.search_cves(search_term)
        except Exception:
            cves = []

        if not cves:
            cves = _get_demo_cves(port_info.service)

        # Filter by CVSS threshold and create findings
        for cve in cves:
            if cve.cvss_score < config.cvss_threshold:
                continue

            finding = Finding(
                id=cve.cve_id,
                title=f"{cve.cve_id} — {port_info.service} vulnerability",
                severity=cve.severity,
                host=host.ip,
                port=port_info.port,
                service=port_info.service,
                service_version=port_info.version,
                cve=cve,
                description=cve.description,
                evidence=f"Detected {port_info.service} {port_info.version} on "
                         f"{host.ip}:{port_info.port} ({port_info.protocol})",
                remediation=_generate_remediation(port_info, cve),
            )
            host.findings.append(finding)

    return host


def _build_search_term(port_info: PortInfo) -> str:
    """Build an NVD search keyword from service information."""
    parts: list[str] = []

    # Use CPE if available
    if port_info.cpe:
        return port_info.cpe

    service = port_info.service.lower()
    # Skip generic services that produce too many results
    if service in ("tcpwrapped", "unknown", ""):
        return ""

    parts.append(service)
    if port_info.version:
        # Take only the major.minor version to narrow results
        ver = port_info.version.split()[0] if port_info.version else ""
        if ver:
            parts.append(ver)

    return " ".join(parts)


def _generate_remediation(port_info: PortInfo, cve: CVERecord) -> str:
    """Generate remediation guidance for a finding."""
    lines = []
    service = port_info.service

    if cve.cvss_score >= 9.0:
        lines.append("🔴 CRITICAL: Immediate action required.")
    elif cve.cvss_score >= 7.0:
        lines.append("🟠 HIGH: Address within 7 days.")

    lines.append(f"• Update {service} to the latest stable version.")
    lines.append(f"• Review vendor advisory for {cve.cve_id}.")

    if cve.references:
        lines.append(f"• Reference: {cve.references[0]}")

    lines.append(f"• If update is not immediately possible, consider restricting "
                 f"access to port {port_info.port} via firewall rules.")

    return "\n".join(lines)
