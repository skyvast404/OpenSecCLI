# OpenSecCLI

> Turn any security API into a CLI command with one YAML file.

English | [中文文档](./README.zh-CN.md)

[![npm version](https://img.shields.io/npm/v/openseccli?style=flat-square)](https://www.npmjs.com/package/openseccli)
[![Node.js](https://img.shields.io/node/v/openseccli?style=flat-square)](https://nodejs.org)
[![License](https://img.shields.io/github/license/user/OpenSecCLI?style=flat-square)](./LICENSE)

```bash
npm install -g openseccli
```

```bash
$ opensec nvd cve-get CVE-2024-3094
┌───────────────┬────────────┬──────────┬──────────┬─────────────────────┬──────────────────────────────────────┐
│ cve_id        │ cvss_score │ severity │ status   │ published           │ description                          │
├───────────────┼────────────┼──────────┼──────────┼─────────────────────┼──────────────────────────────────────┤
│ CVE-2024-3094 │ 10         │ CRITICAL │ Modified │ 2024-03-29T17:15:21 │ Malicious code was discovered in ... │
└───────────────┴────────────┴──────────┴──────────┴─────────────────────┴──────────────────────────────────────┘
1 item · 1.0s · from nvd
```

## Highlights

- **62 commands** across 19 providers — recon, vuln scanning, secrets, supply-chain, cloud, forensics, agent security, SAST, and more
- **6 pure-TypeScript adapters** with zero external dependencies (header-audit, cors-check, hash-id, http-request, race-test, ci-audit)
- **22 Claude Code Skills** — AI-powered investigation & pentest workflows (IOC investigate, code audit, incident response, web/API/network pentest, agent security, etc.)
- **Multi-source enrichment** — query 5 threat intel APIs in parallel, get a consensus verdict
- **One YAML file = one command** — contributors don't need to write TypeScript
- **Pipe-native** — stdin/stdout, `--json`, `--silent`, compatible with ProjectDiscovery ecosystem
- **5 output formats** — table, JSON, CSV, YAML, Markdown
- **Inspired by [OpenCLI](https://github.com/jackwener/opencli)** — same architecture, security-focused

## Quick Start

```bash
# No API key needed — works immediately
opensec nvd cve-search --keyword log4j --limit 5
opensec abuse.ch threatfox-search --ioc 185.220.101.34
opensec crtsh cert-search --domain example.com
opensec abuse.ch feodo-list --limit 10

# Add API keys to unlock more sources
opensec auth add virustotal --api-key
opensec auth add abuseipdb --api-key

# Multi-source IP enrichment (the killer feature)
opensec enrichment ip-enrich 185.220.101.34
```

## Multi-Source Enrichment

One command. Five sources. Parallel queries. Consensus verdict.

```bash
$ opensec enrichment ip-enrich 185.220.101.34

  Source        Status   Verdict      Detail
  AbuseIPDB     ok       Malicious    abuse_score: 100, country: DE, total_reports: 847
  VirusTotal    ok       Malicious    malicious: 12, as_owner: Hetzner
  GreyNoise     ok       Malicious    classification: malicious, noise: true
  ipinfo        ok       -            country: DE, org: Hetzner, city: Falkenstein
  ThreatFox     ok       Known IOC    threat_type: botnet_cc, malware: Cobalt Strike
```

Only queries sources you have API keys for. ThreatFox is always free.

## Built-in Commands

### No API Key Required

| Provider | Command | Description |
|----------|---------|-------------|
| abuse.ch | `opensec abuse.ch urlhaus-query --url <url>` | URLhaus malicious URL check |
| abuse.ch | `opensec abuse.ch malwarebazaar-query --hash <hash>` | MalwareBazaar malware sample lookup |
| abuse.ch | `opensec abuse.ch threatfox-search --ioc <ioc>` | ThreatFox IOC search |
| abuse.ch | `opensec abuse.ch feodo-list` | Feodo Tracker botnet C&C list |
| abuse.ch | `opensec abuse.ch sslbl-search --hash <sha1>` | SSLBL malicious SSL cert search |
| NVD | `opensec nvd cve-get <cve-id>` | CVE details |
| NVD | `opensec nvd cve-search --keyword <term>` | CVE keyword search |
| crt.sh | `opensec crtsh cert-search --domain <domain>` | Certificate transparency search |

### API Key Required (free tier)

| Provider | Command | Free Tier |
|----------|---------|-----------|
| AbuseIPDB | `opensec abuseipdb ip-check <ip>` | 1,000/day |
| VirusTotal | `opensec virustotal hash-lookup <hash>` | 500/day |
| VirusTotal | `opensec virustotal ip-lookup <ip>` | 500/day |
| VirusTotal | `opensec virustotal domain-lookup <domain>` | 500/day |
| GreyNoise | `opensec greynoise ip-check <ip>` | 50/day |
| ipinfo | `opensec ipinfo ip-lookup <ip>` | 50K/month |
| Shodan | `opensec shodan host-lookup <ip>` | Limited |

### Multi-Source Enrichment

| Command | Sources |
|---------|---------|
| `opensec enrichment ip-enrich <ip>` | AbuseIPDB + VirusTotal + GreyNoise + ipinfo + ThreatFox |

### Recon

| Command | Backend | Description |
|---------|---------|-------------|
| `opensec recon subdomain-enum <domain>` | subfinder / amass | Subdomain enumeration |
| `opensec recon tech-fingerprint <target>` | httpx / whatweb | Technology fingerprinting |
| `opensec recon port-scan <target>` | nmap / masscan | Port scanning |
| `opensec recon content-discover <url>` | ffuf / dirsearch | Content / directory discovery |

### Vulnerability Scanning

| Command | Backend | Description |
|---------|---------|-------------|
| `opensec vuln nuclei-scan <target>` | nuclei | Template-based vulnerability scan |
| `opensec vuln nikto-scan <target>` | nikto | Web server scanner |
| `opensec vuln header-audit <url>` | pure TS | Security header analysis (zero deps) |
| `opensec vuln tls-check <host>` | testssl.sh | TLS/SSL configuration check |
| `opensec vuln cors-check <url>` | pure TS | CORS misconfiguration check (zero deps) |
| `opensec vuln api-discover <url>` | kiterunner / ffuf | API endpoint discovery |

### Secrets Detection

| Command | Backend | Description |
|---------|---------|-------------|
| `opensec secrets trufflehog-scan <target>` | trufflehog | Secrets scanning in repos/filesystems |

### Supply Chain

| Command | Backend | Description |
|---------|---------|-------------|
| `opensec supply-chain dep-audit [path]` | npm-audit + pip-audit + trivy | Dependency vulnerability audit |
| `opensec supply-chain ci-audit [path]` | pure TS | CI config security check (zero deps) |
| `opensec supply-chain sbom [path]` | syft | Software bill of materials generation |

### Cloud Security

| Command | Backend | Description |
|---------|---------|-------------|
| `opensec cloud iac-scan [path]` | checkov / terrascan | Infrastructure-as-code scanning |
| `opensec cloud container-scan <image>` | trivy / grype | Container image vulnerability scan |
| `opensec cloud kube-audit` | kube-bench | Kubernetes CIS benchmark audit |

### Forensics

| Command | Backend | Description |
|---------|---------|-------------|
| `opensec forensics file-analyze <file>` | file + exiftool + strings + binwalk | File metadata & content analysis |
| `opensec forensics binary-check <binary>` | checksec | Binary security feature check |
| `opensec forensics pcap-summary <pcap>` | tshark | PCAP traffic summary |
| `opensec forensics apk-analyze <apk>` | aapt + strings | Android APK static analysis |

### Crypto

| Command | Backend | Description |
|---------|---------|-------------|
| `opensec crypto hash-id <hash>` | pure TS | Identify hash type + hashcat/john format (zero deps) |

### Pentest Utilities

| Command | Backend | Description |
|---------|---------|-------------|
| `opensec pentest http-request <url>` | pure TS | Crafted HTTP request sender (zero deps) |
| `opensec pentest race-test <url>` | pure TS | Concurrent race condition tester (zero deps) |
| `opensec pentest fuzz <url>` | pure TS | Parameter fuzzing with security payloads |

### Agent Security

| Command | Description |
|---------|-------------|
| `opensec agent-security scan-skill <path>` | Scan Claude Code skills for prompt injection, data exfiltration, credential exposure |
| `opensec agent-security mcp-audit <path>` | Audit MCP server tool descriptions for poisoning and rug-pull risks |
| `opensec agent-security grade-results <file>` | Grade agent security test results (SAFE/UNSAFE/BLOCKED/INCONCLUSIVE) |
| `opensec agent-security analyze-coverage <file>` | Analyze attack corpus coverage against OWASP ASI Top 10 and MITRE ATLAS |
| `opensec agent-security defense-validation <file>` | Validate defense effectiveness with precision/recall/F1 scoring |
| `opensec agent-security manage-kb` | Manage agent security knowledge base (attack patterns, detection rules) |
| `opensec agent-security normalize-cases <file>` | Normalize raw security test sources into canonical attack case format |
| `opensec agent-security generate-variants <file>` | Expand suite manifests into concrete mutated test cases |
| `opensec agent-security write-report <file>` | Generate agent security assessment report from grading results |

### SAST & Scan Pipeline

| Command | Description |
|---------|-------------|
| `opensec scan full <path>` | Full security scan pipeline: discover, analyze, report |
| `opensec scan discover <path>` | Build security-focused project map (languages, frameworks, entry points) |
| `opensec scan analyze <path>` | Run static analysis (semgrep, gitleaks) with custom rules |
| `opensec scan report <path>` | Generate scan reports (JSON, SARIF, Markdown) |
| `opensec scan entrypoints <path>` | Find HTTP routes, RPC handlers, and other entry points |
| `opensec scan git-signals <path>` | Extract security-relevant commits from git history |
| `opensec scan context-builder <path>` | Build security-focused code context bundles for LLM analysis |
| `opensec scan triage-memory` | Manage triage memory for false-positive tracking and skip logic |
| `opensec scan benchmark <path>` | Run scanner benchmarks and measure detection quality (precision/recall/F1) |

## Claude Code Skills

22 AI-powered investigation & pentest workflows, available as Claude Code slash commands:

| Skill | Description |
|-------|-------------|
| `ioc-investigate` | Deep-dive IOC analysis across multiple threat intel sources |
| `code-security-audit` | Automated source code security review |
| `incident-response` | Guided incident response triage and evidence collection |
| `cve-impact-check` | Assess CVE impact on your infrastructure |
| `attack-surface-map` | Map external attack surface for a domain/org |
| `domain-recon` | Full domain reconnaissance and intelligence gathering |
| `web-pentest` | Web application penetration testing workflow |
| `api-pentest` | API security testing workflow |
| `network-pentest` | Network penetration testing workflow |
| `supply-chain-audit` | Supply chain security audit |
| `cloud-audit` | Cloud security posture assessment |
| `whitebox-code-review` | White-box code security review |
| `business-logic-test` | Business logic vulnerability testing |
| `exploit-validation` | Exploit validation and proof-of-concept |
| `semantic-hunter` | Semantic vulnerability hunting |
| `security-triage` | Security finding triage and prioritization |
| `missed-patch-hunter` | Find missed patches and incomplete fixes |
| `detect-semantic-attack` | Detect semantic attacks in code |
| `agent-security-suite` | Agent/LLM security testing suite |
| `agent-attack-research` | Agent attack research and analysis |
| `ctf-toolkit` | CTF challenge solving toolkit |
| `ai-llm-pentest` | AI/LLM application penetration testing |

## Output Formats

```bash
opensec nvd cve-get CVE-2024-3094                 # table (default)
opensec nvd cve-get CVE-2024-3094 --format json    # JSON
opensec nvd cve-get CVE-2024-3094 --format csv     # CSV
opensec nvd cve-get CVE-2024-3094 --format yaml    # YAML
opensec nvd cve-get CVE-2024-3094 --json            # shorthand
```

Data goes to stdout, status to stderr. Piping always works:

```bash
opensec nvd cve-search --keyword log4j --json | jq '.[].cve_id'
opensec abuse.ch feodo-list --format csv > botnet_c2.csv
echo "CVE-2024-3094" | opensec nvd cve-get --json
```

## Pipe with ProjectDiscovery

Follows the `-json` / `-silent` / stdin conventions:

```bash
subfinder -d target.com -silent | opensec enrichment domain-enrich --json
cat ips.txt | opensec abuseipdb ip-check --json | jq 'select(.abuse_score > 80)'
cat hashes.txt | opensec virustotal hash-lookup --json
```

## Authentication

```bash
opensec auth add virustotal --api-key     # interactive prompt, encrypted storage
opensec auth add abuseipdb --api-key
opensec auth list                          # show configured providers
opensec auth test virustotal               # verify connectivity
opensec auth remove virustotal             # remove credentials
```

Credentials stored in `~/.openseccli/auth/` with 600 permissions. Environment variable override: `OPENSECCLI_VIRUSTOTAL_API_KEY`.

## Contributing

**Adding a new security API takes one YAML file.** No TypeScript required.

```yaml
# src/adapters/urlscan/scan.yaml
provider: urlscan
name: scan
description: Submit URL for scanning
strategy: API_KEY
auth: urlscan

args:
  url:
    type: string
    required: true

pipeline:
  - request:
      url: https://urlscan.io/api/v1/scan/
      method: POST
      headers:
        API-Key: "{{ auth.api_key }}"
      body:
        url: "{{ args.url }}"
  - map:
      template:
        uuid: "{{ item.uuid }}"
        result_url: "{{ item.result }}"

columns: [uuid, result_url]
```

See [CONTRIBUTING.md](./CONTRIBUTING.md) for the full guide.

### APIs waiting for adapters

urlscan.io, Censys, SecurityTrails, Pulsedive, PhishTank, Hybrid Analysis, AlienVault OTX, EmailRep.io, IBM X-Force, Hunter.io, CIRCL hashlookup, MaxMind GeoLite2, Tor Exit Node List — [see Issues](../../issues).

## Detection Upgrades

Recent additions to the vuln/scan engine:

- **CSP parser** — full Content-Security-Policy directive analysis in `header-audit`
- **Cookie analyzer** — SameSite, Secure, HttpOnly, Prefix validation
- **Payload library** — built-in fuzzing payloads for XSS, SQLi, path traversal
- **Custom semgrep rules** — project-specific SAST rules shipped in `scan/rules/`

## Architecture

Built on [OpenCLI](https://github.com/jackwener/opencli) patterns:

- **YAML + TypeScript** dual-track adapters
- **Pipeline engine** — `request → select → map → filter → sort → limit → enrich`
- **Singleton registry** via `globalThis`
- **Manifest compilation** — YAML compiled to JSON at build time
- **Plugin system** — `opensec plugin install github:user/repo`
- **Lifecycle hooks** — `onStartup`, `onBeforeExecute`, `onAfterExecute`

See [BLUEPRINT.md](./BLUEPRINT.md) for architecture details.

## License

[Apache-2.0](./LICENSE)
