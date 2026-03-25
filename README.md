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

- **16 adapters** across 10 security providers — 8 work with zero configuration
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
