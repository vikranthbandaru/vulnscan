"""
CLI Entry Point for VulnScan

Provides a professional command-line interface with authorization
enforcement, target specification, and output configuration.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from rich.console import Console

from scanner import __version__
from scanner.config import DEFAULT_PORTS, ScanConfig
from scanner.engine import VulnScanner

console = Console()


def build_parser() -> argparse.ArgumentParser:
    """Build the argparse CLI parser."""
    parser = argparse.ArgumentParser(
        prog="vulnscan",
        description=(
            "[VulnScan] Automated Vulnerability Scanner\n"
            "   Discover hosts, scan ports, map CVEs, check web security,\n"
            "   and generate professional PDF/JSON/Markdown reports."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  vulnscan -t 192.168.1.1 --confirm-authorized\n"
            "  vulnscan -t scanme.nmap.org -p 1-1024 --format all --confirm-authorized\n"
            "  vulnscan -t 10.0.0.0/24 --cvss-threshold 7.0 --confirm-authorized\n"
            "\n"
            "WARNING: This tool must only be used on systems you are authorized to scan.\n"
            "   Unauthorized scanning is illegal and unethical."
        ),
    )

    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )

    # Required
    parser.add_argument(
        "-t", "--targets",
        nargs="+",
        required=True,
        metavar="TARGET",
        help="Target IPs, CIDR ranges, or domains (e.g., 192.168.1.1 10.0.0.0/24 example.com)",
    )

    parser.add_argument(
        "--confirm-authorized",
        action="store_true",
        required=True,
        help="REQUIRED: Confirm you are authorized to scan the specified targets",
    )

    # Optional
    parser.add_argument(
        "-p", "--ports",
        default=DEFAULT_PORTS,
        help=f"Port specification (default: {DEFAULT_PORTS}). Use 'top1000' for top 1000 ports.",
    )
    parser.add_argument(
        "-o", "--output-dir",
        default="./reports",
        help="Output directory for reports (default: ./reports)",
    )
    parser.add_argument(
        "--format",
        nargs="+",
        default=["all"],
        choices=["json", "pdf", "markdown", "all"],
        help="Output format(s) (default: all)",
    )
    parser.add_argument(
        "--cvss-threshold",
        type=float,
        default=4.0,
        help="Minimum CVSS score for CVE reporting (default: 4.0)",
    )
    parser.add_argument(
        "--nvd-api-key",
        default=None,
        help="NVD API key for higher rate limits (optional)",
    )
    parser.add_argument(
        "--rate-limit",
        type=int,
        default=3,
        help="Max web requests per second (default: 3)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="Network timeout in seconds (default: 10)",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output",
    )

    return parser


def main(argv: list[str] | None = None) -> None:
    """Main CLI entry point."""
    parser = build_parser()
    args = parser.parse_args(argv)

    # Authorization gate
    if not args.confirm_authorized:
        console.print(
            "[bold red]✗ Authorization required![/bold red]\n"
            "  You must pass [bold]--confirm-authorized[/bold] to acknowledge\n"
            "  that you have explicit permission to scan the target systems.\n\n"
            "  Unauthorized scanning is [bold red]illegal[/bold red] and [bold red]unethical[/bold red].",
        )
        sys.exit(1)

    # Handle 'top1000' shortcut
    from scanner.config import TOP_1000_PORTS
    ports = TOP_1000_PORTS if args.ports.lower() == "top1000" else args.ports

    config = ScanConfig(
        targets=args.targets,
        ports=ports,
        output_dir=Path(args.output_dir),
        formats=args.format,
        cvss_threshold=args.cvss_threshold,
        nvd_api_key=args.nvd_api_key,
        rate_limit=args.rate_limit,
        confirm_authorized=args.confirm_authorized,
        verbose=args.verbose,
        timeout=args.timeout,
    )

    scanner = VulnScanner(config)
    scanner.run()


if __name__ == "__main__":
    main()
