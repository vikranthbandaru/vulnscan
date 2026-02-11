"""
Phase 1 — Asset Discovery

Validates target inputs and performs host discovery using nmap ping
scans to build an inventory of live hosts.
"""

from __future__ import annotations

import socket
from typing import TYPE_CHECKING

from rich.console import Console

from scanner.models import HostResult, HostStatus, Target

if TYPE_CHECKING:
    from scanner.config import ScanConfig

console = Console()


def validate_targets(raw_targets: list[str]) -> list[Target]:
    """Parse and validate a list of raw target strings into Target objects."""
    targets: list[Target] = []
    for raw in raw_targets:
        for item in raw.replace(",", " ").split():
            item = item.strip()
            if not item:
                continue
            try:
                targets.append(Target(raw=item))
            except Exception as exc:
                console.print(f"[yellow]⚠ Skipping invalid target {item!r}: {exc}[/yellow]")
    return targets


def resolve_hostname(target: Target) -> str:
    """Resolve a domain to its IP for scanning."""
    if target.target_type == "domain":
        try:
            ip = socket.gethostbyname(target.raw)
            console.print(f"  [dim]Resolved {target.raw} → {ip}[/dim]")
            return ip
        except socket.gaierror:
            console.print(f"[yellow]⚠ Cannot resolve {target.raw}[/yellow]")
            return ""
    return target.raw


def discover_hosts(targets: list[Target], config: "ScanConfig") -> list[HostResult]:
    """
    Perform host discovery on validated targets.

    Uses nmap ping scan (-sn) when available, falling back to a simple
    TCP connect probe on ports 80/443.
    """
    hosts: list[HostResult] = []
    seen: set[str] = set()

    for target in targets:
        ip = resolve_hostname(target)
        if not ip or ip in seen:
            continue
        seen.add(ip)

        host = HostResult(
            ip=ip,
            hostname=target.raw if target.target_type == "domain" else "",
        )

        # Try nmap ping scan
        try:
            host = _nmap_discovery(ip, target, config)
        except Exception:
            # Fallback to TCP probe
            host = _tcp_probe(ip, target)

        hosts.append(host)

    return hosts


def _nmap_discovery(ip: str, target: Target, config: "ScanConfig") -> HostResult:
    """Use python-nmap for host discovery."""
    import nmap  # type: ignore[import-untyped]

    nm = nmap.PortScanner()
    nm.scan(hosts=ip, arguments="-sn -T4")

    host = HostResult(
        ip=ip,
        hostname=target.raw if target.target_type == "domain" else "",
    )

    if ip in nm.all_hosts():
        state = nm[ip].state()
        host.status = HostStatus.UP if state == "up" else HostStatus.DOWN
        # Try to extract response time from scan stats
        try:
            elapsed = float(nm.scanstats().get("elapsed", 0))
            host.response_time_ms = round(elapsed * 1000, 2)
        except (ValueError, TypeError):
            pass
    else:
        host.status = HostStatus.DOWN

    return host


def _tcp_probe(ip: str, target: Target, ports: tuple[int, ...] = (80, 443, 22)) -> HostResult:
    """Fallback: simple TCP connect probe to common ports."""
    import time

    host = HostResult(
        ip=ip,
        hostname=target.raw if target.target_type == "domain" else "",
        status=HostStatus.DOWN,
    )

    for port in ports:
        try:
            start = time.perf_counter()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((ip, port))
            elapsed = (time.perf_counter() - start) * 1000
            sock.close()
            if result == 0:
                host.status = HostStatus.UP
                host.response_time_ms = round(elapsed, 2)
                break
        except OSError:
            continue

    return host
