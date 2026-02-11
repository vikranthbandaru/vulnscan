# 🛡️ VulnScan — Automated Vulnerability Scanner

[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

A **production-ready**, vulnerability scanner built in Python. Discovers hosts, scans ports, maps CVEs from the NVD database, checks web application security, and generates professional **PDF/JSON/Markdown** reports.

---

## Features

| Phase | Capability |
|-------|-----------|
| **Asset Discovery** | ICMP/TCP host discovery with nmap + fallback probes |
| **Port Scanning** | Service version detection, banner grabbing, OS fingerprinting |
| **CVE Mapping** | NVD API v2.0 lookups with CVSS scoring and risk classification |
| **Web Checks** | TLS/SSL assessment, security headers, misconfiguration detection |
| **Reporting** | PDF with severity pie charts, JSON, and Markdown formats |

### Additional Highlights
- **Authorization enforced** — `--confirm-authorized` flag required
- **Rate limiting** — configurable req/s to avoid DoS
- **Rich terminal UI** — progress bars, color-coded severity, ASCII banner
- **Audit trail** — full activity log for compliance
- **Offline mode** — built-in demo CVE database when NVD is unreachable
- **Extensible** — clean Pydantic models, modular architecture

---

## Quick Start

### Prerequisites
- **Python 3.9+**
- **nmap** installed and on PATH ([download](https://nmap.org/download))

### Installation

```bash
# Clone the repo
git clone https://github.com/yourusername/vulnscan.git
cd vulnscan

# Install dependencies
pip install -r requirements.txt

# Or install as a package
pip install -e .
```

### Usage

```bash
# Basic scan (authorization required)
vulnscan -t 192.168.1.1 --confirm-authorized

# Scan a domain with all report formats
vulnscan -t scanme.nmap.org --confirm-authorized --format all -o ./reports

# Scan a CIDR range, top 1000 ports, high severity only
vulnscan -t 10.0.0.0/24 -p top1000 --cvss-threshold 7.0 --confirm-authorized

# Multiple targets with NVD API key for faster lookups
vulnscan -t 192.168.1.1 example.com -p 22,80,443 \
    --nvd-api-key YOUR_KEY --confirm-authorized

# Verbose mode
vulnscan -t 127.0.0.1 --confirm-authorized -v
```

Or run directly:
```bash
python main.py -t 127.0.0.1 --confirm-authorized
```

---

## Project Structure

```
vulnscan/
├── scanner/
│   ├── __init__.py          # Package init + version
│   ├── models.py            # Pydantic data models
│   ├── config.py            # Constants & ScanConfig
│   ├── discovery.py         # Phase 1: Host discovery
│   ├── port_scanner.py      # Phase 2: Port scanning
│   ├── vuln_mapper.py       # Phase 3: CVE correlation
│   ├── web_checks.py        # Phase 4: Web security checks
│   ├── reporter.py          # Phase 5: Report generation
│   ├── engine.py            # Scan orchestrator
│   └── cli.py               # CLI entry point
├── tests/
│   └── test_scanner.py      # Unit tests
├── main.py                  # Direct runner
├── pyproject.toml           # Project metadata
├── requirements.txt         # Dependencies
├── Dockerfile               # Container support
└── README.md
```

---

## CLI Reference

| Flag | Description | Default |
|------|-------------|---------|
| `-t, --targets` | Target IPs, CIDRs, or domains | *required* |
| `--confirm-authorized` | Acknowledge scan authorization | *required* |
| `-p, --ports` | Port specification | `1-1024` |
| `-o, --output-dir` | Report output directory | `./reports` |
| `--format` | Output format(s): json, pdf, markdown, all | `all` |
| `--cvss-threshold` | Minimum CVSS score for findings | `4.0` |
| `--nvd-api-key` | NVD API key for higher rate limits | *none* |
| `--rate-limit` | Max web requests/sec | `3` |
| `--timeout` | Network timeout (seconds) | `10` |
| `-v, --verbose` | Verbose output | `false` |

---

## Report Outputs

### PDF Report
Professional styled report with:
- Cover page with risk score
- Executive summary with severity pie chart
- Methodology section
- Color-coded findings table
- Detailed finding pages with evidence and remediation
- Appendix with scan metadata
- Legal disclaimer

### JSON Report
Machine-readable `findings_<timestamp>.json` with complete scan data including hosts, ports, services, CVEs, and risk scores.

### Markdown Report
Human-readable report with tables, emoji severity indicators, and full finding details. Convertible to HTML for web hosting.

---

## Testing

```bash
# Run all tests
python -m pytest tests/ -v

# Run with coverage
python -m pytest tests/ -v --cov=scanner
```

---

## Docker

```bash
# Build the image
docker build -t vulnscan .

# Run a scan
docker run --rm vulnscan -t scanme.nmap.org --confirm-authorized
```

---

## Legal & Ethics

> **WARNING:** This tool must only be used on systems you have **explicit written authorization** to scan. Unauthorized network scanning is **illegal** in most jurisdictions.

- The `--confirm-authorized` flag is **mandatory** — the scanner will not run without it
- All activities are logged to an audit trail
- No exploitation is attempted — **detection only**
- Reports include legal disclaimers
- Rate limiting prevents accidental DoS

---

## License

MIT License — see [LICENSE](LICENSE) for details.
