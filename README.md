# Privilege Escalation Scanner (privesc)

[![Go Version](https://img.shields.io/badge/Go-1.19%2B-blue)](https://golang.org)
[![License](https://img.shields.io/badge/License-MIT-green)](./LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux%2FWindows%2FmacOS-lightgrey)]
[![Security](https://img.shields.io/badge/Security-Penetration%20Testing-red)]

---

## Overview

**Privilege Escalation Scanner (privesc)** is an enterprise-grade security tool designed to identify, prioritise and optionally exploit privilege escalation vectors across hybrid infrastructures. It supports Linux and Windows hosts, Active Directory environments, and cloud platforms (AWS, Azure, GCP, Kubernetes), and provides detailed, actionable reports and a real-time web interface for live monitoring.

This README documents installation, configuration, usage and contribution guidelines for developers and operators using `privesc` for authorised security testing and risk assessment.

---

## Key Features

- **Multi-platform support**: Linux, Windows, macOS (limited), containers and Active Directory.
- **Comprehensive scanning modules**:
  - Linux: SUID/SGID discovery, sudo misconfigurations, kernel and container escape checks, capabilities, cron jobs, writable files.
  - Windows: UAC bypass checks, unsafe service permissions, registry weaknesses, token analysis.
  - Active Directory: DCSync checks, Kerberoasting support, BloodHound data collection and LDAP enumeration.
  - Cloud: IAM misconfigurations and privilege issues for AWS, Azure, GCP, and Kubernetes RBAC/ServiceAccount checks.
  - Network: SMB/RPC enumeration, LSA secrets checks, RID cycling and null-session detection.
  - Web & DB: JWT/API tests, XSS/SQL injection checks, file upload analysis, plus DB privilege assessment (MySQL, PostgreSQL, MongoDB, Redis).
- **Auto-exploitation (optional)**: Controlled automated exploitation of high-risk findings (disabled in audit mode).
- **Stealth & tuning**: Stealth mode, request delays, rate limiting and thread control for low-impact scans.
- **Distributed scanning**: Master/agent architecture for large-scale assessments.
- **Machine learning**: Anomaly detection and risk scoring to prioritise findings.
- **Extensible plugin system**: Add custom modules and checks.
- **Real-time web UI**: Live dashboards and JSON export for integration with external systems.

---

## Installation

> Supported: Linux, Windows, macOS (partial). Requires Go 1.19 or later for building from source.

### Recommended: download binary (Linux example)

```bash
# Download latest release for linux/amd64
wget https://github.com/your-org/privesc/releases/latest/download/privesc-linux-amd64 -O privesc
chmod +x privesc
sudo mv privesc /usr/local/bin/privesc
```

### Build from source

```bash
git clone https://github.com/your-org/privesc.git
cd privesc
# download Go modules
go mod download
# build
go build -o privesc main.go
# move to system path (optional)
sudo mv privesc /usr/local/bin/
```

### Docker

```bash
docker pull your-org/privesc:latest
# run with local output mounted
docker run --rm -it -v $(pwd):/output your-org/privesc -target 192.168.1.100
```

### Dependencies (recommended)

- `smbclient`, `rpcclient`, `nmap` (network and SMB modules)
- `impacket` (Python package) for advanced AD features (`pip install impacket`)
- `ldapsearch`, `snmpwalk`, `dig` for optional network enumeration

---

## Quick Start

Scan local host (deep scan):

```bash
privesc -deep -output local_scan.json
```

Full network + cloud + web scan:

```bash
privesc -target 192.168.1.100 -deep -cloud -network -webscan -dbscan -output comprehensive_report.json
```

Start web interface on port 8080:

```bash
privesc -web 8080
```

---

## Command-line Options (high-level)

**General options**

- `-target` : target hostname or IP (default: `localhost`)
- `-deep` : enable deep scan mode (default: `false`)
- `-stealth` : enable stealth scanning with delays (default: `false`)
- `-output` : output file (default: `privilege_escalation_report.json`)
- `-exploit` : enable automatic exploitation of high-risk findings (default: `false`)
- `-audit` : audit-only mode (disables exploitation and phishing; recommended for production)
- `-web` : start web UI and bind to specified port (default: `0` = off)
- `-threads` : number of concurrent worker threads (default: `10`)
- `-delay` : delay between requests in ms (default: `100`)
- `-timeout` : network timeout in seconds (default: `30`)
- `-loglevel` : logging level (`DEBUG`, `INFO`, `WARN`, `ERROR`)

**SMB / RPC / AD options**

- `-smbuser`, `-smbpass`, `-smbdomain` : SMB credentials
- `-kerberos` : enable Kerberos enumeration
- `-ridcycle` : enable RID cycling
- `-rid-min`, `-rid-max`, `-rid-step` : RID cycling parameters
- `-lsasecrets` : attempt to enumerate LSA secrets
- `-force-write-test` : attempt harmless write test (mkdir; rmdir) on writable shares

**Cloud options**

- `-cloud` : enable cloud checks (AWS, Azure, GCP, Kubernetes)
- `-aws-region`, `-azure-tenant`, `-gcp-project`, `-kubeconfig`

**Advanced & safety**

- `-distributed`, `-master`, `-agent` : distributed scanning options
- `-ml` : enable machine learning features
- `-no-exploit`, `-no-phishing` : explicitly disable destructive modules
- `-ratelimit`, `-retry` : rate limiting and retry behaviour
- `-exploitdb-update`, `-cve-feed` : update local exploit/CVE feeds

Use `privesc -h` for a full list of flags and module-specific options.

---

## Typical Use Cases and Examples

### 1) Comprehensive enterprise scan

```bash
privesc -target dc01.corp.example.com \
  -deep \
  -cloud \
  -network \
  -bloodhound \
  -smbuser administrator \
  -smbpass 'P@ssw0rd!' \
  -kerberos \
  -ridcycle \
  -output enterprise_scan.json \
  -threads 20 -timeout 60
```

### 2) Stealth assessment (audit safe)

```bash
privesc -target 10.0.1.50 -stealth -delay 500 -threads 5 -audit -no-exploit -output stealth_audit.json
```

### 3) Cloud infrastructure review

```bash
privesc -target cloud-instance -cloud -aws-region us-east-1 -webscan -dbscan -output cloud_assessment.json
```

---

## Output and Reporting

All scans produce a structured JSON report containing:

- `scan_info`: target, timestamp, scan type and aggregate risk level
- `system_info`: OS details, hostname and hardware information
- `findings`: high/medium/low counts and individual findings
- `detailed_results`: per-module detailed objects (suid_binaries, sudo_permissions, kernel_exploits, etc.)

Example CLI snippet to run a scan and view summary:

```bash
privesc -target 192.168.1.100 -deep -output scan.json
jq '.scan_info, .findings' scan.json
```

**Risk classification**
- `CRITICAL`: immediate privilege escalation possible
- `HIGH`: significant misconfiguration
- `MEDIUM`: conditional or chained exploit vectors
- `LOW`: informational or low-impact issues

---

## Safety & Legal Considerations

- **Authorization**: Only run `privesc` against systems and environments for which you have explicit permission. Unauthorized scanning or exploitation can be illegal and cause harm.
- **Audit mode**: Use `-audit` in production or on systems where changes are unacceptable. Audit mode disables exploitation and phishing features.
- **Exploit caution**: `-exploit` may alter system state. Confirm approvals and maintenance windows before enabling.
- **Data protection**: Scan outputs may contain sensitive information (credentials, secrets). Treat reports as sensitive artifacts and store them securely.

---

## Troubleshooting

**Missing dependencies**

```bash
# Ubuntu/Debian
sudo apt-get update && sudo apt-get install -y smbclient rpcclient nmap

# CentOS/RHEL
sudo yum install -y samba-client nmap
```

**Permission errors**

- For comprehensive local checks, run with elevated privileges (`sudo`) when permitted.
- For AD/SMB checks, ensure provided credentials have sufficient scope.

**Network timeouts**

- Increase `-timeout` and `-retry` for slow or high-latency links.

---

## Contributing

Contributions are welcome. Please follow the project contribution workflow:

1. Fork the repository.
2. Create a feature branch: `git checkout -b feat/your-feature`.
3. Implement changes and unit tests.
4. Run tests: `make test`.
5. Create a pull request with a clear description and testing notes.

Please consult `CONTRIBUTING.md` in the repository for detailed guidelines, code style and security disclosure policy.

---

## Development

Suggested development tasks and commands:

```bash
# Set up dev environment (example)
make dev-setup

# Run unit tests
make test

# Build development binary
make build-dev
```
