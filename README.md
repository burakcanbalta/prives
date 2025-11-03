
# Privilege Escalation Scanner (privesc)

[![Go Version](https://img.shields.io/badge/Go-1.19%2B-blue)](https://golang.org)
[![License](https://img.shields.io/badge/License-MIT-green)](./LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux%2FWindows%2FmacOS-lightgrey)]
[![Security](https://img.shields.io/badge/Security-Penetration%20Testing-red)]

---

## Overview

**Privilege Escalation Scanner (privesc)** is an enterprise-grade security tool designed to identify, prioritise, and — where authorised — automatically exploit privilege escalation vectors across hybrid infrastructures. It supports Linux and Windows hosts, Active Directory environments, and cloud platforms (AWS, Azure, GCP, Kubernetes). `privesc` produces actionable, JSON-structured reports and offers a real-time web interface for monitoring scan progress and results.

This document describes installation, usage, configuration, reporting, and contribution guidelines for authorised security testing and risk assessment.

---

## Key Features

- **Multi-platform support:** Linux, Windows, macOS (partial), containers, and Active Directory.
- **Comprehensive scanning modules**:
  - **Linux:** SUID/SGID discovery, sudo misconfigurations, kernel and container escape checks, capabilities, cron jobs, and writable files detection.
  - **Windows:** UAC bypass checks, insecure service permissions, registry weaknesses, and token privilege analysis.
  - **Active Directory:** DCSync checks, Kerberoasting support, BloodHound data collection, and LDAP enumeration.
  - **Cloud:** IAM misconfigurations and privilege issues for AWS, Azure, GCP, and Kubernetes RBAC/ServiceAccount checks.
  - **Network:** SMB/RPC enumeration, LSA secrets analysis, RID cycling, and null-session detection.
  - **Web & DB:** JWT/API tests, XSS/SQL injection checks, file upload analysis, and database privilege assessments for MySQL, PostgreSQL, MongoDB, and Redis.
- **Auto-exploitation (optional):** Controlled automatic exploitation of high-risk findings (disabled in audit mode).
- **Stealth & tuning:** Stealth mode, configurable request delays, rate limiting, and thread control for low-impact scans.
- **Distributed scanning:** Master/agent architecture for large-scale assessments.
- **Machine learning:** Anomaly detection and risk scoring to prioritise findings.
- **Extensible plugin system:** Integrate custom modules and checks.
- **Real-time web UI:** Live dashboards and JSON exports for integration with external systems.

---

## Requirements

- Supported OS: Linux, Windows, macOS (partial).
- Go >= 1.19 (for building from source).
- Recommended: 2 GB RAM (4 GB recommended), 500 MB free disk.

### Optional dependencies (for full functionality)

- `smbclient`, `rpcclient`, `nmap` (network and SMB modules)
- `impacket` (Python package — `pip install impacket`) for advanced AD features
- `ldapsearch`, `snmpwalk`, `dig` for extended network enumeration

---

## Installation

### Recommended: Download binary (Linux example)

```bash
# Download latest release (example)
wget https://github.com/your-org/privesc/releases/latest/download/privesc-linux-amd64 -O privesc
chmod +x privesc
sudo mv privesc /usr/local/bin/privesc
```

### Build from source

```bash
git clone https://github.com/your-org/privesc.git
cd privesc
go mod download
go build -o privesc main.go
sudo mv privesc /usr/local/bin/
```

### Docker

```bash
docker pull your-org/privesc:latest
docker run --rm -it -v $(pwd):/output your-org/privesc -target 192.168.1.100
```

---

## Quick Start

Scan the local host (deep scan):

```bash
privesc -deep -output local_scan.json
```

Full network + cloud + web scan:

```bash
privesc -target 192.168.1.100 -deep -cloud -network -webscan -dbscan -output comprehensive_report.json
```

Start the web interface on port 8080:

```bash
privesc -web 8080
```

---

## Command-line Options (summary)

**General**
- `-target` : Target hostname or IP (default: `localhost`)
- `-deep` : Enable deep scan mode
- `-stealth` : Enable stealth scanning with delays
- `-output` : Output file (default: `privilege_escalation_report.json`)
- `-exploit` : Enable automatic exploitation of high-risk findings
- `-audit` : Audit-only mode (disables exploitation and phishing)
- `-web` : Start web UI and bind to specified port
- `-threads` : Concurrent worker threads (default: `10`)
- `-delay` : Delay between requests in ms (default: `100`)
- `-timeout` : Network timeout in seconds (default: `30`)
- `-loglevel` : `DEBUG`, `INFO`, `WARN`, `ERROR`

**SMB / RPC / AD**
- `-smbuser`, `-smbpass`, `-smbdomain` : SMB credentials
- `-kerberos` : Enable Kerberos enumeration
- `-ridcycle` : Enable RID cycling
- `-rid-min`, `-rid-max`, `-rid-step` : RID cycling parameters
- `-lsasecrets` : Attempt to enumerate LSA secrets
- `-force-write-test` : Attempt harmless write tests (mkdir; rmdir)

**Cloud**
- `-cloud` : Enable cloud checks (AWS, Azure, GCP, Kubernetes)
- `-aws-region`, `-azure-tenant`, `-gcp-project`, `-kubeconfig`

**Advanced & Safety**
- `-distributed`, `-master`, `-agent` : Distributed scanning options
- `-ml` : Enable ML features
- `-no-exploit`, `-no-phishing` : Explicitly disable destructive modules
- `-ratelimit`, `-retry` : Rate limiting and retry behaviour
- `-exploitdb-update`, `-cve-feed` : Update local exploit/CVE feeds

Use `privesc -h` for a complete list of flags and module-specific options.

---

## Typical Use Cases & Examples

**Comprehensive enterprise scan**

```bash
privesc -target dc01.corp.example.com \
  -deep -cloud -network -bloodhound \
  -smbuser administrator -smbpass 'P@ssw0rd!' \
  -kerberos -ridcycle \
  -output enterprise_scan.json -threads 20 -timeout 60
```

**Stealth assessment (audit-safe)**

```bash
privesc -target 10.0.1.50 -stealth -delay 500 -threads 5 -audit -no-exploit -output stealth_audit.json
```

**Cloud infrastructure review**

```bash
privesc -target cloud-instance -cloud -aws-region us-east-1 -webscan -dbscan -output cloud_assessment.json
```

---

## Output and Reporting

All scans generate a structured JSON report with:

- `scan_info`: target, timestamp, scan type, duration, version, aggregate risk level
- `system_info`: OS, architecture, hostname, current user, kernel
- `findings`: high/medium/low counts and totals
- `detailed_results`: per-module objects (suid_binaries, sudo_permissions, kernel_exploits, etc.)

Risk classification:
- `CRITICAL`: Immediate privilege escalation possible
- `HIGH`: Significant misconfiguration
- `MEDIUM`: Conditional or chained vectors
- `LOW`: Informational

Example CLI to summarise results:

```bash
privesc -target 192.168.1.100 -deep -output scan.json
jq '.scan_info, .findings' scan.json
```

---

## Example Report (excerpt)

```json
{
  "scan_info": { "target": "192.168.1.100", "timestamp": "2024-01-15T14:30:25Z", "duration": "2m45s", "scan_type": "Comprehensive Privilege Escalation", "version": "2.1.0", "risk_level": "HIGH" },
  "system_info": { "os": "Linux", "architecture": "x86_64", "hostname": "ubuntu-server", "current_user": "security", "kernel": "5.15.0-91-generic" },
  "findings": { "high_risk_findings": 3, "medium_risk_findings": 8, "low_risk_findings": 12, "total_findings": 23, "overall_risk": "HIGH" }
}
```

---

## Web Interface & API

When run with `-web <port>`, `privesc` exposes:
- Dashboard: `http://<host>:<port>`
- API endpoints (examples):
  - `GET /api/results` – JSON results
  - `GET /api/logs` – Scan logs
  - `GET /api/scan` – Current scan status

The UI displays live progress, interactive exploit suggestions, and export options.

---

## Troubleshooting

**Missing dependencies**

Ubuntu/Debian:
```bash
sudo apt-get update && sudo apt-get install -y smbclient rpcclient nmap
```

CentOS/RHEL:
```bash
sudo yum install -y samba-client nmap
```

**Permission errors**
- Run with elevated privileges (`sudo`) when permitted.
- Ensure credentials used for AD/SMB checks have appropriate scope.

**Network timeouts**
- Increase `-timeout` and `-retry` for high-latency networks.

---

## Contributing

Contributions are welcome. Please follow the project workflow:
1. Fork the repo.
2. Create a feature branch: `git checkout -b feat/your-feature`.
3. Implement changes and tests.
4. Run tests: `make test`.
5. Create a pull request with a clear description and testing notes.

Refer to `CONTRIBUTING.md` for code style and disclosure policies.

---

## Development

Suggested commands:

```bash
make dev-setup
make test
make build-dev
```

A `Makefile` and GitHub Actions CI are recommended for consistent builds and testing.
