"""
Scanner Orchestrator Engine

Coordinates all five scanning phases with live progress display,
error handling, and audit trail logging.
"""

from __future__ import annotations

import logging
import time
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING

from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table
from rich.text import Text

from scanner import __version__
from scanner.config import ScanConfig
from scanner.discovery import discover_hosts, validate_targets
from scanner.models import HostResult, HostStatus, ScanMetadata, ScanResult, Severity
from scanner.port_scanner import scan_ports
from scanner.reporter import save_json, save_markdown, save_pdf
from scanner.vuln_mapper import map_vulnerabilities
from scanner.web_checks import run_web_checks

if TYPE_CHECKING:
    pass

console = Console()
logger = logging.getLogger("vulnscan")


# ── Banner ────────────────────────────────────────────────────────────────────

BANNER = r"""
[bold blue]
 ██╗   ██╗██╗   ██╗██╗     ███╗   ██╗███████╗ ██████╗ █████╗ ███╗   ██╗
 ██║   ██║██║   ██║██║     ████╗  ██║██╔════╝██╔════╝██╔══██╗████╗  ██║
 ██║   ██║██║   ██║██║     ██╔██╗ ██║███████╗██║     ███████║██╔██╗ ██║
 ╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║╚════██║██║     ██╔══██║██║╚██╗██║
  ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║███████║╚██████╗██║  ██║██║ ╚████║
   ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
[/bold blue]
[dim]  Automated Vulnerability Scanner v{version}[/dim]
[dim]  ─────────────────────────────────────────[/dim]
"""


def print_banner() -> None:
    console.print(BANNER.format(version=__version__))


# ── Engine ────────────────────────────────────────────────────────────────────

class VulnScanner:
    """Main scanner engine — orchestrates all scan phases."""

    def __init__(self, config: ScanConfig) -> None:
        self.config = config
        self.result = ScanResult(
            metadata=ScanMetadata(
                scanner_version=__version__,
                targets_requested=config.targets,
                ports_scanned=config.ports,
                cvss_threshold=config.cvss_threshold,
                authorization_confirmed=config.confirm_authorized,
            )
        )
        self._setup_logging()

    def _setup_logging(self) -> None:
        """Configure audit trail logging."""
        self.config.output_dir.mkdir(parents=True, exist_ok=True)
        log_file = self.config.output_dir / "scan_audit.log"
        handler = logging.FileHandler(log_file, encoding="utf-8")
        handler.setFormatter(logging.Formatter(
            "%(asctime)s | %(levelname)-8s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        ))
        logger.addHandler(handler)
        logger.setLevel(logging.DEBUG if self.config.verbose else logging.INFO)
        logger.info("Scan initiated — targets: %s", self.config.targets)

    def run(self) -> ScanResult:
        """Execute the full scan pipeline."""
        print_banner()
        self.result.metadata.scan_start = datetime.now().isoformat()
        start_time = time.time()

        try:
            self._phase1_discovery()
            self._phase2_port_scan()
            self._phase3_vuln_mapping()
            self._phase4_web_checks()
            self._phase5_reports()
        except KeyboardInterrupt:
            console.print("\n[yellow]⚡ Scan interrupted by user — generating partial report…[/yellow]")
            logger.warning("Scan interrupted by user (Ctrl-C)")
        except Exception as exc:
            console.print(f"\n[red]✗ Unexpected error: {exc}[/red]")
            logger.exception("Unexpected error during scan")

        self.result.metadata.scan_end = datetime.now().isoformat()
        self.result.compute_summary()

        elapsed = time.time() - start_time
        self._print_summary(elapsed)
        logger.info("Scan completed in %.1f seconds", elapsed)

        return self.result

    # ── Phase 1 ───────────────────────────────────────────────────────────

    def _phase1_discovery(self) -> None:
        console.print(Panel.fit(
            "[bold]Phase 1: Asset Discovery[/bold]",
            border_style="blue",
        ))
        logger.info("Phase 1: Asset Discovery")

        targets = validate_targets(self.config.targets)
        if not targets:
            console.print("[red]✗ No valid targets. Aborting.[/red]")
            raise SystemExit(1)

        console.print(f"  Validated [cyan]{len(targets)}[/cyan] target(s)")

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("Discovering hosts…", total=len(targets))
            hosts = discover_hosts(targets, self.config)
            progress.update(task, completed=len(targets))

        self.result.hosts = hosts
        up_count = sum(1 for h in hosts if h.status == HostStatus.UP)
        console.print(f"  Found [green]{up_count}[/green] live host(s) out of {len(hosts)}\n")
        logger.info("Discovery complete: %d/%d hosts up", up_count, len(hosts))

    # ── Phase 2 ───────────────────────────────────────────────────────────

    def _phase2_port_scan(self) -> None:
        live_hosts = [h for h in self.result.hosts if h.status == HostStatus.UP]
        if not live_hosts:
            console.print("[yellow]⚠ No live hosts — skipping port scan.[/yellow]\n")
            return

        console.print(Panel.fit(
            "[bold]Phase 2: Port Scanning & Service Detection[/bold]",
            border_style="blue",
        ))
        logger.info("Phase 2: Port Scanning (%d hosts)", len(live_hosts))

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("Scanning ports…", total=len(live_hosts))
            for host in live_hosts:
                progress.update(task, description=f"Scanning {host.ip}…")
                scan_ports(host, self.config)
                progress.advance(task)

        total_ports = sum(len(h.ports) for h in live_hosts)
        console.print(f"  Discovered [cyan]{total_ports}[/cyan] open port(s)\n")
        logger.info("Port scan complete: %d open ports", total_ports)

    # ── Phase 3 ───────────────────────────────────────────────────────────

    def _phase3_vuln_mapping(self) -> None:
        live_hosts = [h for h in self.result.hosts if h.status == HostStatus.UP]
        hosts_with_services = [h for h in live_hosts if h.ports]
        if not hosts_with_services:
            console.print("[yellow]⚠ No services found — skipping CVE mapping.[/yellow]\n")
            return

        console.print(Panel.fit(
            "[bold]Phase 3: Vulnerability Mapping (CVE Correlation)[/bold]",
            border_style="blue",
        ))
        logger.info("Phase 3: Vulnerability Mapping (%d hosts)", len(hosts_with_services))

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("Mapping vulnerabilities…", total=len(hosts_with_services))
            for host in hosts_with_services:
                progress.update(task, description=f"CVE lookup: {host.ip}…")
                map_vulnerabilities(host, self.config)
                progress.advance(task)

        total_findings = sum(len(h.findings) for h in hosts_with_services)
        console.print(f"  Mapped [cyan]{total_findings}[/cyan] potential vulnerability findings\n")
        logger.info("Vulnerability mapping complete: %d findings", total_findings)

    # ── Phase 4 ───────────────────────────────────────────────────────────

    def _phase4_web_checks(self) -> None:
        live_hosts = [h for h in self.result.hosts if h.status == HostStatus.UP]
        http_hosts = [
            h for h in live_hosts
            if any(
                p.service.lower() in ("http", "https", "http-proxy", "https-alt")
                or p.port in (80, 443, 8080, 8443)
                for p in h.ports
            )
        ]
        if not http_hosts:
            console.print("[yellow]⚠ No HTTP services — skipping web checks.[/yellow]\n")
            return

        console.print(Panel.fit(
            "[bold]Phase 4: Web Application Security Checks[/bold]",
            border_style="blue",
        ))
        logger.info("Phase 4: Web checks (%d hosts)", len(http_hosts))

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("Running web checks…", total=len(http_hosts))
            for host in http_hosts:
                progress.update(task, description=f"Web checks: {host.ip}…")
                run_web_checks(host, self.config)
                progress.advance(task)

        console.print("  Web application checks complete\n")
        logger.info("Web checks complete")

    # ── Phase 5 ───────────────────────────────────────────────────────────

    def _phase5_reports(self) -> None:
        console.print(Panel.fit(
            "[bold]Phase 5: Report Generation[/bold]",
            border_style="blue",
        ))
        logger.info("Phase 5: Report Generation")

        self.result.compute_summary()
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        out = self.config.output_dir

        if self.config.should_json:
            save_json(self.result, out / f"findings_{timestamp}.json")

        if self.config.should_markdown:
            save_markdown(self.result, out / f"vulnerability_report_{timestamp}.md")

        if self.config.should_pdf:
            try:
                save_pdf(self.result, out / f"vulnerability_report_{timestamp}.pdf")
            except Exception as exc:
                console.print(f"  [yellow]⚠ PDF generation failed: {exc}[/yellow]")
                logger.error("PDF generation failed: %s", exc)

        console.print("")

    # ── Summary Display ───────────────────────────────────────────────────

    def _print_summary(self, elapsed: float) -> None:
        s = self.result.summary

        table = Table(
            title="Scan Summary",
            border_style="blue",
            show_header=True,
            header_style="bold white on dark_blue",
        )
        table.add_column("Metric", style="bold")
        table.add_column("Value", justify="right")

        table.add_row("Hosts Scanned", str(s.total_hosts))
        table.add_row("Hosts Online", str(s.hosts_up))
        table.add_row("Open Ports", str(s.total_ports_open))
        table.add_row("Total Findings", str(s.total_findings))
        table.add_row("")
        table.add_row(
            Text("Critical", style="bold red"), str(s.critical_count)
        )
        table.add_row(
            Text("High", style="dark_orange"), str(s.high_count)
        )
        table.add_row(
            Text("Medium", style="yellow"), str(s.medium_count)
        )
        table.add_row(
            Text("Low", style="blue"), str(s.low_count)
        )
        table.add_row(
            Text("Info", style="dim"), str(s.info_count)
        )
        table.add_row("")
        table.add_row("Risk Score", f"{s.overall_risk_score}/10")
        table.add_row("Scan Duration", f"{elapsed:.1f}s")

        console.print(table)
        console.print(f"\n[dim]Reports saved to: {self.config.output_dir.resolve()}[/dim]\n")
