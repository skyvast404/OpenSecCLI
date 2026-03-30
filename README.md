<p align="center">
  <strong>One CLI for your entire security workflow.</strong>
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/openseccli"><img src="https://img.shields.io/npm/v/openseccli?style=flat-square&color=cb3837" alt="npm"></a>
  <a href="https://nodejs.org"><img src="https://img.shields.io/node/v/openseccli?style=flat-square&color=339933" alt="node"></a>
  <a href="./LICENSE"><img src="https://img.shields.io/github/license/user/OpenSecCLI?style=flat-square" alt="license"></a>
  <img src="https://img.shields.io/badge/tests-337%20passed-brightgreen?style=flat-square" alt="tests">
  <img src="https://img.shields.io/badge/commands-84-blue?style=flat-square" alt="commands">
  <img src="https://img.shields.io/badge/claude%20code%20skills-35-blueviolet?style=flat-square" alt="skills">
</p>

<p align="center">
  English | <a href="./README.zh-CN.md">中文文档</a>
</p>

---

<p align="center">
  <img src="demo/demo.gif" alt="OpenSecCLI Demo" width="800">
</p>

## What is OpenSecCLI?

OpenSecCLI unifies **84 security commands** across **20 providers** and **11 domains** into a single CLI. Query threat intel, scan for vulnerabilities, pentest APIs, audit cloud infrastructure, assess agent security -- all with consistent JSON output and pipe-friendly design.

Built for **security professionals** who want one tool instead of twenty. Built for **AI agents** that need structured output and predictable error handling.

```bash
npm install -g openseccli
```

## Quick Demo

```bash
# Multi-source threat intel -- queries 5 APIs in parallel, returns consensus verdict
$ opensec enrichment ip-enrich 203.0.113.5

  Source        Status   Verdict      Detail
  AbuseIPDB     ok       Malicious    abuse_score: 100, country: DE, total_reports: 847
  VirusTotal    ok       Malicious    malicious: 12, as_owner: Hetzner
  GreyNoise     ok       Malicious    classification: malicious, noise: true
  ipinfo        ok       -            country: DE, org: Hetzner, city: Falkenstein
  ThreatFox     ok       Known IOC    threat_type: botnet_cc, malware: Cobalt Strike

# Full security header audit with A-F grading (zero external deps)
$ opensec vuln header-audit --url https://example.com

# Fuzz parameters with built-in XSS/SQLi/traversal payloads
$ opensec pentest fuzz --url "https://target.com/search?q=test" --payloads xss

# Scan MCP server tools for prompt injection & rug-pull risks
$ opensec agent-security mcp-audit ./mcp-config.json

# CVE lookup -- no API key needed
$ opensec nvd cve-get CVE-2024-3094
┌───────────────┬────────────┬──────────┬──────────┬─────────────────────┬──────────────────────────────────────┐
│ cve_id        │ cvss_score │ severity │ status   │ published           │ description                          │
├───────────────┼────────────┼──────────┼──────────┼─────────────────────┼──────────────────────────────────────┤
│ CVE-2024-3094 │ 10         │ CRITICAL │ Modified │ 2024-03-29T17:15:21 │ Malicious code was discovered in ... │
└───────────────┴────────────┴──────────┴──────────┴─────────────────────┴──────────────────────────────────────┘
```

## Why OpenSecCLI?

| | Without OpenSecCLI | With OpenSecCLI |
|---|---|---|
| **Threat Intel** | 5 different APIs, 5 different auth flows, 5 output formats | `opensec enrichment ip-enrich <ip>` |
| **Vuln Scanning** | Install nuclei + nikto + testssl + custom scripts | `opensec vuln nuclei-scan <target>` |
| **Agent Security** | No standard tooling exists | `opensec agent-security mcp-audit <path>` |
| **Output** | Parse each tool differently | `--format json\|csv\|yaml\|table\|markdown` everywhere |
| **Automation** | Glue scripts between tools | Pipe stdin/stdout, JSON errors, exit 0 for empty results |

## Install

### npm (recommended)

```bash
npm install -g openseccli
opensec --help
```

### Docker

```bash
# Lite (~200 MB) -- pure-TS adapters, no external tools needed
docker build -t opensec .
docker run -it opensec vuln header-audit --url https://example.com

# Full (~3 GB) -- includes nuclei, subfinder, semgrep, trivy, and 40+ tools
docker build -t opensec-full --target full .
docker run -it opensec-full vuln nuclei-scan https://target.com
```

### From Source

```bash
git clone https://github.com/user/OpenSecCLI.git
cd OpenSecCLI
npm install
npm run build
node dist/main.js --help
```

## Commands at a Glance

**84 commands** organized across 11 security domains. 10 commands run with **zero external dependencies** (pure TypeScript).

<details>
<summary><strong>Threat Intelligence</strong> -- 8 commands (no API key needed)</summary>

| Command | Description |
|---------|-------------|
| `opensec abuse.ch urlhaus-query --url <url>` | URLhaus malicious URL check |
| `opensec abuse.ch malwarebazaar-query --hash <hash>` | MalwareBazaar malware sample lookup |
| `opensec abuse.ch threatfox-search --ioc <ioc>` | ThreatFox IOC search |
| `opensec abuse.ch feodo-list` | Feodo Tracker botnet C&C list |
| `opensec abuse.ch sslbl-search --hash <sha1>` | SSLBL malicious SSL cert search |
| `opensec nvd cve-get <cve-id>` | CVE details |
| `opensec nvd cve-search --keyword <term>` | CVE keyword search |
| `opensec crtsh cert-search --domain <domain>` | Certificate transparency search |

</details>

<details>
<summary><strong>Threat Intelligence</strong> -- 6 commands (free-tier API key)</summary>

| Command | Free Tier |
|---------|-----------|
| `opensec abuseipdb ip-check <ip>` | 1,000/day |
| `opensec virustotal hash-lookup <hash>` | 500/day |
| `opensec virustotal ip-lookup <ip>` | 500/day |
| `opensec virustotal domain-lookup <domain>` | 500/day |
| `opensec greynoise ip-check <ip>` | 50/day |
| `opensec ipinfo ip-lookup <ip>` | 50K/month |
| `opensec shodan host-lookup <ip>` | Limited |

</details>

<details>
<summary><strong>Multi-Source Enrichment</strong> -- 4 commands</summary>

| Command | Sources |
|---------|---------|
| `opensec enrichment ip-enrich <ip>` | AbuseIPDB + VirusTotal + GreyNoise + ipinfo + ThreatFox |
| `opensec enrichment domain-enrich <domain>` | Multi-source domain intelligence |
| `opensec enrichment hash-enrich <hash>` | Multi-source hash reputation |
| `opensec enrichment url-enrich <url>` | Multi-source URL analysis |

</details>

<details>
<summary><strong>Recon</strong> -- 10 commands</summary>

| Command | Backend |
|---------|---------|
| `opensec recon subdomain-enum <domain>` | subfinder / amass |
| `opensec recon tech-fingerprint <target>` | httpx / whatweb |
| `opensec recon port-scan <target>` | nmap / masscan |
| `opensec recon fast-scan <target>` | masscan |
| `opensec recon content-discover <url>` | ffuf / dirsearch |
| `opensec recon dns-resolve <domain>` | dnsx |
| `opensec recon url-crawl <url>` | katana |
| `opensec recon url-archive <domain>` | gau |
| `opensec recon wayback-urls <domain>` | waybackurls |
| `opensec recon web-spider <url>` | gospider |
| `opensec recon param-discover <url>` | paramspider |
| `opensec recon osint-harvest <domain>` | theHarvester |

</details>

<details>
<summary><strong>Vulnerability Scanning</strong> -- 9 commands</summary>

| Command | Backend |
|---------|---------|
| `opensec vuln nuclei-scan <target>` | nuclei |
| `opensec vuln nikto-scan <target>` | nikto |
| `opensec vuln header-audit <url>` | **pure TS** -- CSP parsing, cookie analysis, A-F grading |
| `opensec vuln tls-check <host>` | testssl.sh |
| `opensec vuln cors-check <url>` | **pure TS** -- CORS misconfiguration detection |
| `opensec vuln api-discover <url>` | kiterunner / ffuf |
| `opensec vuln xss-scan <url>` | dalfox |
| `opensec vuln crlf-scan <url>` | crlfuzz |
| `opensec vuln graphql-audit <url>` | graphql introspection |

</details>

<details>
<summary><strong>Pentest Utilities</strong> -- 5 commands</summary>

| Command | Backend |
|---------|---------|
| `opensec pentest http-request <url>` | **pure TS** -- crafted HTTP requests |
| `opensec pentest race-test <url>` | **pure TS** -- concurrent race condition tester |
| `opensec pentest fuzz <url>` | **pure TS** -- parameter fuzzing with XSS/SQLi/traversal payloads |
| `opensec pentest jwt-test <token>` | **pure TS** -- JWT vulnerability testing |
| `opensec pentest sqli-scan <url>` | sqlmap |
| `opensec pentest cmdi-scan <url>` | commix |

</details>

<details>
<summary><strong>SAST & Scan Pipeline</strong> -- 11 commands</summary>

| Command | Description |
|---------|-------------|
| `opensec scan full <path>` | Full pipeline: discover, analyze, report |
| `opensec scan discover <path>` | Build security-focused project map |
| `opensec scan analyze <path>` | Static analysis (semgrep, gitleaks) + custom rules |
| `opensec scan report <path>` | Generate reports (JSON, SARIF, Markdown) |
| `opensec scan entrypoints <path>` | Find HTTP routes, RPC handlers, entry points |
| `opensec scan git-signals <path>` | Extract security-relevant commits |
| `opensec scan context-builder <path>` | Build code context bundles for LLM analysis |
| `opensec scan triage-memory` | False-positive tracking and skip logic |
| `opensec scan benchmark <path>` | Scanner benchmarks (precision/recall/F1) |
| `opensec scan gosec-scan <path>` | Go security scanner |
| `opensec scan bandit-scan <path>` | Python security linter |

</details>

<details>
<summary><strong>Agent Security</strong> -- 9 commands</summary>

| Command | Description |
|---------|-------------|
| `opensec agent-security scan-skill <path>` | Scan Claude Code skills for prompt injection & data exfil |
| `opensec agent-security mcp-audit <path>` | Audit MCP server tools for poisoning & rug-pull risks |
| `opensec agent-security grade-results <file>` | Grade results: SAFE / UNSAFE / BLOCKED / INCONCLUSIVE |
| `opensec agent-security analyze-coverage <file>` | Coverage vs OWASP ASI Top 10 & MITRE ATLAS |
| `opensec agent-security defense-validation <file>` | Precision / recall / F1 scoring |
| `opensec agent-security manage-kb` | Manage attack pattern & detection rule knowledge base |
| `opensec agent-security normalize-cases <file>` | Normalize raw test sources into canonical format |
| `opensec agent-security generate-variants <file>` | Expand suite manifests into mutated test cases |
| `opensec agent-security write-report <file>` | Generate assessment report from grading results |

</details>

<details>
<summary><strong>Supply Chain, Cloud, Secrets, Forensics, Crypto, DAST</strong></summary>

**Supply Chain** (4 commands)

| Command | Backend |
|---------|---------|
| `opensec supply-chain dep-audit [path]` | npm-audit + pip-audit + trivy |
| `opensec supply-chain ci-audit [path]` | **pure TS** -- CI config security check |
| `opensec supply-chain sbom [path]` | syft |
| `opensec supply-chain snyk-scan [path]` | snyk |

**Cloud Security** (6 commands)

| Command | Backend |
|---------|---------|
| `opensec cloud iac-scan [path]` | checkov / terrascan |
| `opensec cloud container-scan <image>` | trivy / grype |
| `opensec cloud kube-audit` | kube-bench |
| `opensec cloud dockerfile-lint <path>` | hadolint |
| `opensec cloud kube-security` | kubesec |
| `opensec cloud container-lint <image>` | dockle |
| `opensec cloud cloud-posture` | prowler / scout suite |

**Secrets** (1 command)

| Command | Backend |
|---------|---------|
| `opensec secrets trufflehog-scan <target>` | trufflehog |

**Forensics** (4 commands)

| Command | Backend |
|---------|---------|
| `opensec forensics file-analyze <file>` | file + exiftool + strings + binwalk |
| `opensec forensics binary-check <binary>` | checksec |
| `opensec forensics pcap-summary <pcap>` | tshark |
| `opensec forensics apk-analyze <apk>` | aapt + strings |

**Crypto** (1 command)

| Command | Backend |
|---------|---------|
| `opensec crypto hash-id <hash>` | **pure TS** -- identify hash type + hashcat/john format |

**DAST** (1 command)

| Command | Backend |
|---------|---------|
| `opensec dast zap-scan <target>` | OWASP ZAP |

</details>

## Claude Code Skills (30)

OpenSecCLI ships **30 AI-powered security workflows** as Claude Code slash commands. Each skill orchestrates multiple `opensec` commands into complete investigation or pentest workflows.

<details>
<summary><strong>Threat Intelligence & Incident Response</strong> (5 skills)</summary>

| Skill | What it does |
|-------|-------------|
| `/ioc-investigate` | Deep-dive IOC analysis across multiple threat intel sources |
| `/incident-response` | Guided triage, evidence collection, containment steps |
| `/cve-impact-check` | Assess CVE impact on your specific infrastructure |
| `/threat-hunting` | Proactive threat hunting across logs and telemetry |
| `/osint-deep-dive` | Open-source intelligence deep investigation |

</details>

<details>
<summary><strong>Penetration Testing</strong> (6 skills)</summary>

| Skill | What it does |
|-------|-------------|
| `/web-pentest` | Full web application pentest workflow |
| `/api-pentest` | API security testing: auth, IDOR, injection, rate limiting |
| `/network-pentest` | Network pentest: scanning, enumeration, exploitation |
| `/ai-llm-pentest` | AI/LLM application pentest: prompt injection, jailbreak, data leak |
| `/bug-bounty-workflow` | End-to-end bug bounty hunting workflow |
| `/red-team-recon` | Red team reconnaissance and initial access |

</details>

<details>
<summary><strong>Code & Application Security</strong> (6 skills)</summary>

| Skill | What it does |
|-------|-------------|
| `/code-security-audit` | Automated source code security review |
| `/whitebox-code-review` | White-box code review with taint analysis |
| `/semantic-hunter` | Semantic vulnerability hunting beyond pattern matching |
| `/detect-semantic-attack` | Detect semantic attacks: backdoors, logic bombs |
| `/business-logic-test` | Business logic flaw testing |
| `/missed-patch-hunter` | Find incomplete fixes and missed patches |

</details>

<details>
<summary><strong>Infrastructure & Supply Chain</strong> (5 skills)</summary>

| Skill | What it does |
|-------|-------------|
| `/supply-chain-audit` | Full supply chain security audit |
| `/cloud-audit` | Cloud security posture assessment |
| `/container-security` | Container and image security assessment |
| `/devsecops-pipeline` | DevSecOps pipeline security review |
| `/compliance-check` | Compliance verification (SOC2, PCI-DSS, HIPAA) |

</details>

<details>
<summary><strong>Agent Security & Research</strong> (4 skills)</summary>

| Skill | What it does |
|-------|-------------|
| `/agent-security-suite` | Full agent/LLM security test suite |
| `/agent-attack-research` | Agent attack research and novel technique discovery |
| `/dast-assessment` | Dynamic application security testing workflow |
| `/ctf-toolkit` | CTF challenge solving toolkit |

</details>

<details>
<summary><strong>Triage & Recon</strong> (4 skills)</summary>

| Skill | What it does |
|-------|-------------|
| `/attack-surface-map` | Map external attack surface for a domain/org |
| `/domain-recon` | Full domain reconnaissance and intelligence |
| `/security-triage` | Security finding triage and prioritization |
| `/exploit-validation` | Exploit validation and PoC development |

</details>

## Agent-Friendly Design

OpenSecCLI is built to be consumed by AI agents and automation pipelines:

```bash
# Structured JSON output on stdout, status messages on stderr
opensec nvd cve-search --keyword log4j --json 2>/dev/null | jq '.[0]'

# Empty results return exit 0 with empty array (not an error)
opensec abuse.ch threatfox-search --ioc "clean-domain.com" --json
# → []

# Pipe from stdin -- compatible with ProjectDiscovery ecosystem
subfinder -d target.com -silent | opensec enrichment domain-enrich --json
cat ips.txt | opensec abuseipdb ip-check --json | jq 'select(.abuse_score > 80)'
echo "CVE-2024-3094" | opensec nvd cve-get --json

# 5 output formats
opensec nvd cve-get CVE-2024-3094 --format json
opensec nvd cve-get CVE-2024-3094 --format csv
opensec nvd cve-get CVE-2024-3094 --format yaml
opensec nvd cve-get CVE-2024-3094 --format markdown
opensec nvd cve-get CVE-2024-3094                      # table (default)
```

## Authentication

```bash
opensec auth add virustotal --api-key     # interactive prompt, encrypted storage
opensec auth add abuseipdb --api-key
opensec auth list                          # show configured providers
opensec auth test virustotal               # verify connectivity
opensec auth remove virustotal             # remove credentials
```

Credentials stored in `~/.openseccli/auth/` with `0600` permissions. Override with environment variables: `OPENSECCLI_VIRUSTOTAL_API_KEY`.

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

For more complex integrations, write a TypeScript adapter. See [CONTRIBUTING.md](./CONTRIBUTING.md).

**Plugin system:** Third-party adapters can be installed to `~/.openseccli/plugins/` via `opensec plugin install github:user/repo`.

### APIs Waiting for Adapters

urlscan.io, Censys, SecurityTrails, Pulsedive, PhishTank, Hybrid Analysis, AlienVault OTX, EmailRep.io, IBM X-Force, Hunter.io, CIRCL hashlookup, MaxMind GeoLite2, Tor Exit Node List -- [see Issues](../../issues).

## Autopilot — One Command Does Everything

```bash
$ opensec autopilot https://target.com

  ═══════════════════════════════════════════
   OpenSecCLI Autopilot Report
  ═══════════════════════════════════════════
   Target: https://target.com
   Grade:  C (54/100)
   Findings: 43 total (2 Critical, 8 High)
   Duration: 18.2s
  ═══════════════════════════════════════════

$ opensec report opensec-report/autopilot-report.json
# → Generates professional HTML report
```

## MCP Server — AI Agent Integration

```bash
# Add to Claude Desktop / Cursor MCP config:
{
  "mcpServers": {
    "opensec": {
      "command": "npx",
      "args": ["openseccli", "mcp"]
    }
  }
}
# Now any AI agent can call 84 security commands as tools
```

## Declarative Workflows

```bash
$ opensec workflow run workflows/web-audit.yaml --target example.com

  [1/4] ✓ Header Audit (1.1s) — 11 findings
  [2/4] ✓ CORS Check (3.3s) — 10 findings
  [3/4] ✓ Certificate Check (0.5s) — 20 findings
  [4/4] ✓ Tech Fingerprint (2.5s) — 1 finding
```

## Architecture

```
Commander.js CLI
    |
    +-- YAML adapters (15) -----> pipeline engine: request -> select -> map -> filter -> sort -> limit -> enrich
    +-- TypeScript adapters (69) -> direct implementation, full control
    |
    +-- Singleton registry (globalThis)
    +-- Manifest compilation (YAML -> JSON at build time)
    +-- Plugin system (~/.openseccli/plugins/, lifecycle hooks)
    +-- Output formatter (table | json | csv | yaml | markdown)
```

Dual adapter system: **YAML** for simple API wrappers (one file, no code), **TypeScript** for complex logic (parsers, multi-step workflows, pure-TS scanners). Both register identically into the command tree.

See [BLUEPRINT.md](./BLUEPRINT.md) for full architecture details.

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=skyvast404/OpenSecCLI&type=Date)](https://star-history.com/#skyvast404/OpenSecCLI&Date)

## License

[Apache-2.0](./LICENSE)
