"""
Phase 4 — Web Application Security Checks

Performs safe, non-intrusive checks on HTTP/HTTPS services:
  • TLS/SSL certificate and cipher assessment
  • HTTP security header analysis
  • Common misconfiguration detection
  • Information disclosure checks

All requests respect a configurable rate limit.
"""

from __future__ import annotations

import re
import socket
import ssl
import time
from datetime import datetime, timezone
from typing import TYPE_CHECKING

import httpx
from rich.console import Console

from scanner.config import (
    DEPRECATED_TLS,
    LEAKY_HEADERS,
    REQUIRED_SECURITY_HEADERS,
)
from scanner.models import Finding, HostResult, PortInfo, Severity

if TYPE_CHECKING:
    from scanner.config import ScanConfig

console = Console()


# ── Rate Limiter ──────────────────────────────────────────────────────────────

class RateLimiter:
    """Simple token-bucket style rate limiter."""

    def __init__(self, max_per_sec: int = 3) -> None:
        self.interval = 1.0 / max_per_sec
        self._last = 0.0

    def wait(self) -> None:
        now = time.time()
        diff = now - self._last
        if diff < self.interval:
            time.sleep(self.interval - diff)
        self._last = time.time()


# ── TLS / SSL Checks ─────────────────────────────────────────────────────────

def check_tls(host: str, port: int = 443, timeout: int = 10) -> list[Finding]:
    """Assess TLS certificate and protocol configuration."""
    findings: list[Finding] = []

    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert(binary_form=False)
                protocol = ssock.version()
                cipher = ssock.cipher()

                # Check protocol version
                if protocol and protocol in DEPRECATED_TLS:
                    findings.append(Finding(
                        id=f"TLS-DEPRECATED-{protocol}",
                        title=f"Deprecated TLS Protocol: {protocol}",
                        severity=Severity.HIGH,
                        host=host,
                        port=port,
                        service="https",
                        description=f"The server supports deprecated protocol {protocol}, "
                                    f"which has known vulnerabilities.",
                        evidence=f"Negotiated protocol: {protocol}",
                        remediation=f"Disable {protocol} and enforce TLS 1.2 or TLS 1.3.",
                    ))
                else:
                    findings.append(Finding(
                        id=f"TLS-OK-{protocol}",
                        title=f"TLS Protocol: {protocol}",
                        severity=Severity.INFO,
                        host=host,
                        port=port,
                        service="https",
                        description=f"Server uses {protocol}.",
                        evidence=f"Protocol: {protocol}",
                        remediation="No action required.",
                    ))

                # Check cipher suite
                if cipher:
                    cipher_name = cipher[0]
                    weak_ciphers = ["RC4", "3DES", "DES", "NULL", "EXPORT"]
                    if any(w in cipher_name.upper() for w in weak_ciphers):
                        findings.append(Finding(
                            id="TLS-WEAK-CIPHER",
                            title=f"Weak Cipher Suite: {cipher_name}",
                            severity=Severity.MEDIUM,
                            host=host,
                            port=port,
                            service="https",
                            description=f"Weak cipher suite {cipher_name} detected.",
                            evidence=f"Cipher: {cipher_name}",
                            remediation="Disable weak ciphers. Use AES-GCM or ChaCha20-Poly1305.",
                        ))

                # Check certificate expiry
                if cert:
                    not_after = cert.get("notAfter", "")
                    if not_after:
                        try:
                            # OpenSSL cert format
                            expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                            expiry = expiry.replace(tzinfo=timezone.utc)
                            now = datetime.now(timezone.utc)
                            days_left = (expiry - now).days

                            if days_left < 0:
                                findings.append(Finding(
                                    id="TLS-CERT-EXPIRED",
                                    title="SSL Certificate Expired",
                                    severity=Severity.CRITICAL,
                                    host=host, port=port, service="https",
                                    description=f"Certificate expired {abs(days_left)} days ago.",
                                    evidence=f"Expiry: {not_after}",
                                    remediation="Renew the SSL/TLS certificate immediately.",
                                ))
                            elif days_left < 30:
                                findings.append(Finding(
                                    id="TLS-CERT-EXPIRING",
                                    title="SSL Certificate Expiring Soon",
                                    severity=Severity.MEDIUM,
                                    host=host, port=port, service="https",
                                    description=f"Certificate expires in {days_left} days.",
                                    evidence=f"Expiry: {not_after}",
                                    remediation="Renew the SSL/TLS certificate before expiry.",
                                ))
                        except (ValueError, TypeError):
                            pass

    except ssl.SSLError as exc:
        findings.append(Finding(
            id="TLS-ERROR",
            title="TLS Connection Error",
            severity=Severity.MEDIUM,
            host=host, port=port, service="https",
            description=f"TLS connection failed: {exc}",
            evidence=str(exc),
            remediation="Verify TLS configuration on the target server.",
        ))
    except (OSError, socket.timeout):
        pass  # Host/port unreachable — skip TLS checks

    return findings


# ── HTTP Security Headers ────────────────────────────────────────────────────

def check_headers(url: str, host: str, port: int, timeout: int = 10) -> list[Finding]:
    """Check for missing or insecure HTTP headers."""
    findings: list[Finding] = []

    try:
        resp = httpx.get(url, timeout=timeout, follow_redirects=True, verify=False)
        headers = resp.headers

        # Missing security headers
        for header in REQUIRED_SECURITY_HEADERS:
            if header.lower() not in {k.lower() for k in headers.keys()}:
                findings.append(Finding(
                    id=f"HDR-MISSING-{header.upper().replace('-', '_')}",
                    title=f"Missing Security Header: {header}",
                    severity=Severity.MEDIUM if header in ("Content-Security-Policy", "Strict-Transport-Security") else Severity.LOW,
                    host=host, port=port, service="http",
                    description=f"The HTTP response is missing the {header} header, "
                                f"which helps protect against common web attacks.",
                    evidence=f"Response headers: {dict(headers)}",
                    remediation=f"Add the {header} header to server responses. "
                                f"Consult OWASP Secure Headers Project for recommended values.",
                ))

        # Information leakage headers
        for header in LEAKY_HEADERS:
            value = headers.get(header, "")
            if value:
                findings.append(Finding(
                    id=f"HDR-LEAK-{header.upper().replace('-', '_')}",
                    title=f"Information Disclosure: {header}",
                    severity=Severity.LOW,
                    host=host, port=port, service="http",
                    description=f"The {header} header reveals server technology information: {value}",
                    evidence=f"{header}: {value}",
                    remediation=f"Remove or suppress the {header} header to reduce information leakage.",
                ))

    except httpx.HTTPError as exc:
        console.print(f"  [yellow]⚠ Header check failed for {url}: {exc}[/yellow]")

    return findings


# ── Misconfiguration Checks ──────────────────────────────────────────────────

def check_misconfigs(url: str, host: str, port: int, timeout: int = 10) -> list[Finding]:
    """Detect common web server misconfigurations."""
    findings: list[Finding] = []

    try:
        resp = httpx.get(url, timeout=timeout, follow_redirects=True, verify=False)
        body = resp.text.lower()

        # Directory listing
        if "index of /" in body or "<title>directory listing" in body:
            findings.append(Finding(
                id="MISCONFIG-DIR-LISTING",
                title="Directory Listing Enabled",
                severity=Severity.MEDIUM,
                host=host, port=port, service="http",
                description="The web server has directory listing enabled, potentially "
                            "exposing sensitive files and directory structure.",
                evidence="Page contains 'Index of /' pattern",
                remediation="Disable directory listing in the web server configuration. "
                            "For Apache: 'Options -Indexes'. For nginx: 'autoindex off;'.",
            ))

        # Default pages
        default_patterns = [
            ("apache", "apache2 ubuntu default page", "Apache default page detected"),
            ("apache", "it works!", "Apache default 'It works!' page"),
            ("nginx", "welcome to nginx", "nginx default welcome page"),
            ("iis", "iis windows server", "IIS default page detected"),
        ]
        for _server, pattern, title in default_patterns:
            if pattern in body:
                findings.append(Finding(
                    id="MISCONFIG-DEFAULT-PAGE",
                    title=title,
                    severity=Severity.LOW,
                    host=host, port=port, service="http",
                    description="A default server page is exposed, indicating the server "
                                "may not be properly configured for production use.",
                    evidence=f"Page contains: '{pattern}'",
                    remediation="Replace default pages with your application content. "
                                "Remove default virtual hosts.",
                ))
                break

        # Verbose error indicators
        error_patterns = [
            r"stack\s*trace", r"traceback", r"syntax\s*error",
            r"sql\s*error", r"mysql_", r"pg_query", r"odbc_",
        ]
        for pattern in error_patterns:
            if re.search(pattern, body):
                findings.append(Finding(
                    id="MISCONFIG-VERBOSE-ERRORS",
                    title="Verbose Error Messages Detected",
                    severity=Severity.MEDIUM,
                    host=host, port=port, service="http",
                    description="The server returns verbose error messages that may reveal "
                                "internal implementation details, database types, or file paths.",
                    evidence=f"Response body matches error pattern: '{pattern}'",
                    remediation="Disable debug/verbose mode in production. Configure custom "
                                "error pages. Never expose stack traces to end users.",
                ))
                break

    except httpx.HTTPError as exc:
        console.print(f"  [yellow]⚠ Misconfig check failed for {url}: {exc}[/yellow]")

    return findings


# ── Orchestrator ──────────────────────────────────────────────────────────────

def run_web_checks(host: HostResult, config: "ScanConfig") -> HostResult:
    """Run all web checks on HTTP/HTTPS ports of a host."""
    limiter = RateLimiter(config.rate_limit)
    http_services = {"http", "https", "http-proxy", "https-alt", "http-alt"}

    for port_info in host.ports:
        service = port_info.service.lower()
        if service not in http_services and port_info.port not in (80, 443, 8080, 8443):
            continue

        scheme = "https" if port_info.port in (443, 8443) or "ssl" in service or "https" in service else "http"
        url = f"{scheme}://{host.ip}:{port_info.port}"

        console.print(f"  [dim]Web checks: {url}[/dim]")

        # TLS checks for HTTPS
        if scheme == "https":
            limiter.wait()
            tls_findings = check_tls(host.ip, port_info.port, config.timeout)
            host.findings.extend(tls_findings)

        # Header checks
        limiter.wait()
        header_findings = check_headers(url, host.ip, port_info.port, config.timeout)
        host.findings.extend(header_findings)

        # Misconfiguration checks
        limiter.wait()
        misconfig_findings = check_misconfigs(url, host.ip, port_info.port, config.timeout)
        host.findings.extend(misconfig_findings)

    return host
