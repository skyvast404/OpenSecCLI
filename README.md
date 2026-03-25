# OpenSecCLI

**The open-source security CLI hub — query, enrich, automate.**

English | [中文](README.zh-CN.md)

Turn any security API into a CLI command with one YAML file. Inspired by [OpenCLI](https://github.com/jackwener/opencli).

```bash
# Install
npm install -g openseccli

# Query a CVE (no API key needed)
opensec nvd cve-get CVE-2024-3094

# Check if an IP is malicious (no API key needed)
opensec abuse.ch threatfox-search --ioc 185.220.101.34

# Search certificate transparency logs
opensec crtsh cert-search --domain example.com

# Multi-source IP enrichment (the killer feature)
opensec enrichment ip-enrich 185.220.101.34

  Source        Verdict      Detail
  AbuseIPDB     Malicious    abuse_score: 100, reports: 847
  GreyNoise     Malicious    classification: malicious, tags: [tor, scanner]
  VirusTotal    Malicious    malicious_votes: 12
  ipinfo        —            country: DE, org: Hetzner
  ThreatFox     Known IOC    malware: Cobalt Strike

  Consensus: MALICIOUS (4/5 sources)

# Pipe with ProjectDiscovery tools
subfinder -d target.com -silent | opensec enrichment domain-enrich --json
cat ips.txt | opensec enrichment ip-enrich --json | jq '.verdict'
```

## Why OpenSecCLI?

| Before | After |
|--------|-------|
| Login to VirusTotal web → paste hash → wait → copy result | `opensec virustotal hash-lookup <sha256>` |
| Check 5 threat intel sources one by one | `opensec enrichment ip-enrich <ip>` (parallel, 1 command) |
| Write a Python script every time you need automation | Write a YAML file, get a CLI command |
| Each tool has different output format | Unified `--format table\|json\|csv` across all commands |

## Available Adapters

### No API Key Required (works out of the box)

| Provider | Command | What it does |
|----------|---------|-------------|
| abuse.ch | `opensec abuse.ch urlhaus-query --url <url>` | Check URL against URLhaus |
| abuse.ch | `opensec abuse.ch malwarebazaar-query --hash <hash>` | Look up malware sample |
| abuse.ch | `opensec abuse.ch threatfox-search --ioc <ioc>` | Search IOC in ThreatFox |
| abuse.ch | `opensec abuse.ch feodo-list` | List botnet C&C servers |
| abuse.ch | `opensec abuse.ch sslbl-search --hash <sha1>` | Search malicious SSL certs |
| NVD | `opensec nvd cve-get <cve-id>` | Get CVE details |
| NVD | `opensec nvd cve-search --keyword <term>` | Search CVEs |
| crt.sh | `opensec crtsh cert-search --domain <domain>` | Certificate transparency |

### Free API Key Required (register to use)

| Provider | Command | Free Tier |
|----------|---------|-----------|
| AbuseIPDB | `opensec abuseipdb ip-check <ip>` | 1,000 checks/day |
| VirusTotal | `opensec virustotal hash-lookup <hash>` | 500 req/day |
| GreyNoise | `opensec greynoise ip-check <ip>` | 50 req/day |
| Shodan | `opensec shodan host-lookup <ip>` | Limited free |
| ipinfo | `opensec ipinfo ip-lookup <ip>` | 50K req/month |

### Multi-Source Enrichment

| Command | Sources |
|---------|---------|
| `opensec enrichment ip-enrich <ip>` | AbuseIPDB + VT + GreyNoise + ipinfo + ThreatFox |
| `opensec enrichment domain-enrich <domain>` | VT + crt.sh + Shodan + WHOIS |
| `opensec enrichment hash-enrich <hash>` | VT + MalwareBazaar + ThreatFox |

## Authentication

```bash
# Add API key (interactive, stored encrypted)
opensec auth add virustotal --api-key
opensec auth add abuseipdb --api-key

# Check configured providers
opensec auth list

# Test connectivity
opensec auth test virustotal
```

## Output Formats

```bash
opensec nvd cve-get CVE-2024-3094                    # table (default)
opensec nvd cve-get CVE-2024-3094 --format json       # JSON
opensec nvd cve-get CVE-2024-3094 --format csv        # CSV
opensec nvd cve-get CVE-2024-3094 --json               # JSON shorthand
opensec nvd cve-get CVE-2024-3094 -o result.json       # save to file
```

All commands output data to stdout and status/errors to stderr, so piping always works:

```bash
opensec nvd cve-search --keyword log4j --json | jq '.[].cve_id'
opensec abuse.ch feodo-list --format csv > botnet_c2.csv
```

## Contributing an Adapter

Adding a new security API takes **one YAML file**:

```yaml
# src/adapters/urlscan/scan.yaml
provider: urlscan
name: scan
description: Submit URL for scanning on urlscan.io
strategy: API_KEY
auth: urlscan

args:
  url:
    type: string
    required: true
    help: URL to scan

pipeline:
  - request:
      url: https://urlscan.io/api/v1/scan/
      method: POST
      headers:
        API-Key: "{{ auth.api_key }}"
        Content-Type: application/json
      body:
        url: "{{ args.url }}"

  - select:
      path: ""

  - map:
      template:
        uuid: "{{ item.uuid }}"
        url: "{{ item.url }}"
        visibility: "{{ item.visibility }}"
        result_url: "{{ item.result }}"

columns: [uuid, url, visibility, result_url]
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full guide.

## Piping with ProjectDiscovery

OpenSecCLI follows ProjectDiscovery conventions (`--json`, `--silent`, stdin support):

```bash
# Enrich subdomains discovered by subfinder
subfinder -d target.com -silent | opensec enrichment domain-enrich --json

# Feed IPs to nuclei after enrichment
cat ips.txt | opensec abuseipdb ip-check --json | \
  jq -r 'select(.abuse_score > 80) | .ip' | nuclei -t cves/

# Bulk IOC check from a file
cat suspicious_hashes.txt | opensec abuse.ch malwarebazaar-query --json
```

## Architecture

Built on the same patterns as [OpenCLI](https://github.com/jackwener/opencli):

- **YAML + TypeScript dual-track adapters** — simple APIs use YAML, complex logic uses TypeScript
- **Pipeline execution engine** — `request → select → map → filter → sort → limit`
- **Singleton command registry** — `globalThis` pattern for module safety
- **Manifest compilation** — YAML compiled to JSON at build time for fast startup
- **Plugin system** — `opensec plugin install github:user/repo`
- **Lifecycle hooks** — `onStartup`, `onBeforeExecute`, `onAfterExecute`

See [BLUEPRINT.md](BLUEPRINT.md) for the full architecture document.

## License

Apache-2.0
