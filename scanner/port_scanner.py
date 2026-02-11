"""
Phase 2 — Port Scanning & Service Fingerprinting

Scans live hosts for open ports, detects service versions and banners,
and performs OS fingerprinting when possible.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from rich.console import Console

from scanner.models import HostResult, PortInfo, PortState

if TYPE_CHECKING:
    from scanner.config import ScanConfig

console = Console()


def scan_ports(host: HostResult, config: "ScanConfig") -> HostResult:
    """
    Perform port scanning and service version detection on a host.

    Uses nmap -sV (version detection) on the configured port range.
    Falls back to basic socket scanning if nmap is unavailable.
    """
    try:
        return _nmap_port_scan(host, config)
    except Exception as exc:
        console.print(f"  [yellow]⚠ nmap scan failed ({exc}), using TCP fallback[/yellow]")
        return _socket_port_scan(host, config)


def _nmap_port_scan(host: HostResult, config: "ScanConfig") -> HostResult:
    """Full nmap port scan with service fingerprinting."""
    import nmap  # type: ignore[import-untyped]

    nm = nmap.PortScanner()
    port_arg = config.ports

    # Build nmap arguments
    arguments = f"-sV -T4 --version-intensity 5 -p {port_arg}"
    if config.verbose:
        arguments += " -v"

    console.print(f"  [dim]nmap {arguments} {host.ip}[/dim]")
    nm.scan(hosts=host.ip, arguments=arguments)

    if host.ip not in nm.all_hosts():
        return host

    host_data = nm[host.ip]

    # OS guess (may require root)
    if "osmatch" in host_data:
        matches = host_data.get("osmatch", [])
        if matches:
            host.os_guess = matches[0].get("name", "")

    # Parse open ports
    for proto in host_data.all_protocols():
        for port_num in sorted(host_data[proto].keys()):
            port_data = host_data[proto][port_num]
            state_str = port_data.get("state", "")

            port_info = PortInfo(
                port=port_num,
                protocol=proto,
                state=_parse_state(state_str),
                service=port_data.get("name", ""),
                version=port_data.get("version", ""),
                banner=port_data.get("extrainfo", ""),
                cpe=port_data.get("cpe", ""),
            )

            # Build a richer version string
            product = port_data.get("product", "")
            version = port_data.get("version", "")
            if product and not port_info.version:
                port_info.version = f"{product} {version}".strip()

            host.ports.append(port_info)

    # Store nmap version in banner for audit
    try:
        nmap_ver = nm.nmap_version()
        if nmap_ver:
            host.os_guess = host.os_guess or ""
    except Exception:
        pass

    return host


def _socket_port_scan(host: HostResult, config: "ScanConfig") -> HostResult:
    """Fallback port scan using raw TCP sockets."""
    import socket
    from scanner.config import DEFAULT_PORTS

    port_spec = config.ports
    ports_to_scan = _parse_port_spec(port_spec or DEFAULT_PORTS)

    for port_num in ports_to_scan:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(config.timeout)
            result = sock.connect_ex((host.ip, port_num))

            if result == 0:
                banner = ""
                try:
                    sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                    banner = sock.recv(1024).decode("utf-8", errors="replace").strip()
                except Exception:
                    pass

                port_info = PortInfo(
                    port=port_num,
                    protocol="tcp",
                    state=PortState.OPEN,
                    service=_guess_service(port_num),
                    banner=banner[:200],
                )
                host.ports.append(port_info)

            sock.close()
        except OSError:
            continue

    return host


def _parse_state(state_str: str) -> PortState:
    """Convert nmap state string to PortState enum."""
    state_map = {"open": PortState.OPEN, "closed": PortState.CLOSED, "filtered": PortState.FILTERED}
    return state_map.get(state_str.lower(), PortState.FILTERED)


def _parse_port_spec(spec: str) -> list[int]:
    """Parse a port specification like '22,80,443' or '1-1024' into a list of ints."""
    ports: list[int] = []
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            try:
                start, end = part.split("-", 1)
                ports.extend(range(int(start), int(end) + 1))
            except ValueError:
                continue
        else:
            try:
                ports.append(int(part))
            except ValueError:
                continue
    return sorted(set(p for p in ports if 1 <= p <= 65535))


_COMMON_SERVICES: dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc",
    139: "netbios-ssn", 143: "imap", 443: "https", 445: "microsoft-ds",
    993: "imaps", 995: "pop3s", 1433: "ms-sql", 1521: "oracle",
    3306: "mysql", 3389: "ms-wbt-server", 5432: "postgresql",
    5900: "vnc", 6379: "redis", 8080: "http-proxy", 8443: "https-alt",
    27017: "mongodb",
}


def _guess_service(port: int) -> str:
    """Best-effort service guess by port number."""
    return _COMMON_SERVICES.get(port, "")
