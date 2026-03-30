# CLI Reference

## Global options

| Flag | Description |
|------|-------------|
| `--format <type>` | Output format: `table` (default), `json`, `csv`, `yaml`, `markdown` |
| `--json` | Shorthand for `--format json` |
| `--help` | Show help |
| `--version` | Show version |

## opensec autopilot

Run full security assessment on a target.

```bash
opensec autopilot <url>
```

| Arg | Required | Description |
|-----|----------|-------------|
| `url` | yes | Target URL |

---

## opensec auth

Manage API credentials.

```bash
opensec auth add <provider> --api-key    # Add credential (interactive)
opensec auth list                        # List configured providers
opensec auth test <provider>             # Verify connectivity
opensec auth remove <provider>           # Remove credential
```

---

## abuse.ch

### urlhaus-query

```bash
opensec abuse.ch urlhaus-query --url <url>
```

| Arg | Required | Description |
|-----|----------|-------------|
| `--url` | yes | URL to check against URLhaus |

**Columns:** `url`, `status`, `threat`, `date_added`, `tags`

### malwarebazaar-query

```bash
opensec abuse.ch malwarebazaar-query --hash <hash>
```

| Arg | Required | Description |
|-----|----------|-------------|
| `--hash` | yes | SHA256/MD5 hash |

**Columns:** `sha256`, `file_type`, `signature`, `first_seen`, `tags`

### threatfox-search

```bash
opensec abuse.ch threatfox-search --ioc <ioc>
```

| Arg | Required | Description |
|-----|----------|-------------|
| `--ioc` | yes | IOC value (IP, domain, URL, hash) |

**Columns:** `ioc`, `ioc_type`, `threat_type`, `malware`, `confidence_level`

### feodo-list

```bash
opensec abuse.ch feodo-list
```

**Columns:** `ip`, `port`, `status`, `last_online`, `malware`

### sslbl-search

```bash
opensec abuse.ch sslbl-search --hash <sha1>
```

| Arg | Required | Description |
|-----|----------|-------------|
| `--hash` | yes | SHA1 fingerprint |

**Columns:** `sha1`, `subject`, `issuer`, `listing_reason`

---

## nvd

### cve-get

```bash
opensec nvd cve-get <cve-id>
```

| Arg | Required | Description |
|-----|----------|-------------|
| `cve-id` | yes | CVE identifier (e.g. CVE-2024-3094) |

**Columns:** `cve_id`, `cvss_score`, `severity`, `status`, `published`, `description`

### cve-search

```bash
opensec nvd cve-search --keyword <term>
```

| Arg | Required | Description |
|-----|----------|-------------|
| `--keyword` | yes | Search term |

**Columns:** `cve_id`, `cvss_score`, `severity`, `published`, `description`

---

## crtsh

### cert-search

```bash
opensec crtsh cert-search --domain <domain>
```

| Arg | Required | Description |
|-----|----------|-------------|
| `--domain` | yes | Domain to search |

**Columns:** `id`, `common_name`, `issuer`, `not_before`, `not_after`

---

## abuseipdb

### ip-check

```bash
opensec abuseipdb ip-check <ip>
```

| Arg | Required | Description |
|-----|----------|-------------|
| `ip` | yes | IP address |

**Columns:** `ip`, `abuse_score`, `country`, `isp`, `total_reports`, `last_reported`

---

## virustotal

### hash-lookup

```bash
opensec virustotal hash-lookup <hash>
```

### ip-lookup

```bash
opensec virustotal ip-lookup <ip>
```

### domain-lookup

```bash
opensec virustotal domain-lookup <domain>
```

---

## greynoise

### ip-check

```bash
opensec greynoise ip-check <ip>
```

**Columns:** `ip`, `noise`, `riot`, `classification`, `name`, `last_seen`

---

## ipinfo

### ip-lookup

```bash
opensec ipinfo ip-lookup <ip>
```

**Columns:** `ip`, `hostname`, `city`, `region`, `country`, `org`

---

## shodan

### host-lookup

```bash
opensec shodan host-lookup <ip>
```

---

## enrichment

### ip-enrich

```bash
opensec enrichment ip-enrich <ip>
```

Queries AbuseIPDB, VirusTotal, GreyNoise, ipinfo, and ThreatFox in parallel.

**Columns:** `source`, `status`, `verdict`, `detail`

### domain-enrich

```bash
opensec enrichment domain-enrich <domain>
```

### hash-enrich

```bash
opensec enrichment hash-enrich <hash>
```

### url-enrich

```bash
opensec enrichment url-enrich <url>
```

---

## recon

### subdomain-enum

```bash
opensec recon subdomain-enum <domain>
```

### tech-fingerprint

```bash
opensec recon tech-fingerprint <target>
```

### port-scan

```bash
opensec recon port-scan <target>
```

### fast-scan

```bash
opensec recon fast-scan <target>
```

### content-discover

```bash
opensec recon content-discover <url>
```

### dns-resolve

```bash
opensec recon dns-resolve <domain>
```

### url-crawl

```bash
opensec recon url-crawl <url>
```

### url-archive

```bash
opensec recon url-archive <domain>
```

### wayback-urls

```bash
opensec recon wayback-urls <domain>
```

### web-spider

```bash
opensec recon web-spider <url>
```

### param-discover

```bash
opensec recon param-discover <url>
```

### osint-harvest

```bash
opensec recon osint-harvest <domain>
```

---

## vuln

### nuclei-scan

```bash
opensec vuln nuclei-scan <target>
```

### nikto-scan

```bash
opensec vuln nikto-scan <target>
```

### header-audit

```bash
opensec vuln header-audit --url <url>
```

**pure TS** — No external deps. Checks security headers, CSP, cookies. Returns A-F grade.

### tls-check

```bash
opensec vuln tls-check <host>
```

### cors-check

```bash
opensec vuln cors-check --url <url>
```

**pure TS** — Detects CORS misconfigurations.

### api-discover

```bash
opensec vuln api-discover <url>
```

### xss-scan

```bash
opensec vuln xss-scan <url>
```

### crlf-scan

```bash
opensec vuln crlf-scan <url>
```

### graphql-audit

```bash
opensec vuln graphql-audit <url>
```

---

## pentest

### http-request

```bash
opensec pentest http-request <url>
```

**pure TS** — Send crafted HTTP requests.

### race-test

```bash
opensec pentest race-test <url>
```

**pure TS** — Concurrent race condition tester.

### fuzz

```bash
opensec pentest fuzz --url <url> --payloads <type>
```

| Arg | Required | Description |
|-----|----------|-------------|
| `--url` | yes | Target URL with parameters |
| `--payloads` | no | Payload type: `xss`, `sqli`, `traversal` |

**pure TS** — Parameter fuzzing with built-in payloads.

### jwt-test

```bash
opensec pentest jwt-test <token>
```

**pure TS** — JWT vulnerability testing (none alg, weak secrets).

### sqli-scan

```bash
opensec pentest sqli-scan <url>
```

### cmdi-scan

```bash
opensec pentest cmdi-scan <url>
```

---

## scan

### full

```bash
opensec scan full <path>
```

### discover

```bash
opensec scan discover <path>
```

### analyze

```bash
opensec scan analyze <path>
```

### report

```bash
opensec scan report <path>
```

### entrypoints

```bash
opensec scan entrypoints <path>
```

### git-signals

```bash
opensec scan git-signals <path>
```

### context-builder

```bash
opensec scan context-builder <path>
```

### triage-memory

```bash
opensec scan triage-memory
```

### benchmark

```bash
opensec scan benchmark <path>
```

### gosec-scan

```bash
opensec scan gosec-scan <path>
```

### bandit-scan

```bash
opensec scan bandit-scan <path>
```

---

## agent-security

### scan-skill

```bash
opensec agent-security scan-skill <path>
```

### mcp-audit

```bash
opensec agent-security mcp-audit <path>
```

### grade-results

```bash
opensec agent-security grade-results <file>
```

### analyze-coverage

```bash
opensec agent-security analyze-coverage <file>
```

### defense-validation

```bash
opensec agent-security defense-validation <file>
```

### manage-kb

```bash
opensec agent-security manage-kb
```

### normalize-cases

```bash
opensec agent-security normalize-cases <file>
```

### generate-variants

```bash
opensec agent-security generate-variants <file>
```

### write-report

```bash
opensec agent-security write-report <file>
```

---

## supply-chain

### dep-audit

```bash
opensec supply-chain dep-audit [path]
```

### ci-audit

```bash
opensec supply-chain ci-audit [path]
```

**pure TS** — CI config security check.

### sbom

```bash
opensec supply-chain sbom [path]
```

### snyk-scan

```bash
opensec supply-chain snyk-scan [path]
```

---

## cloud

### iac-scan

```bash
opensec cloud iac-scan [path]
```

### container-scan

```bash
opensec cloud container-scan <image>
```

### kube-audit

```bash
opensec cloud kube-audit
```

### dockerfile-lint

```bash
opensec cloud dockerfile-lint <path>
```

### kube-security

```bash
opensec cloud kube-security
```

### container-lint

```bash
opensec cloud container-lint <image>
```

### cloud-posture

```bash
opensec cloud cloud-posture
```

---

## secrets

### trufflehog-scan

```bash
opensec secrets trufflehog-scan <target>
```

---

## forensics

### file-analyze

```bash
opensec forensics file-analyze <file>
```

### binary-check

```bash
opensec forensics binary-check <binary>
```

### pcap-summary

```bash
opensec forensics pcap-summary <pcap>
```

### apk-analyze

```bash
opensec forensics apk-analyze <apk>
```

---

## crypto

### hash-id

```bash
opensec crypto hash-id <hash>
```

**pure TS** — Identifies hash type and suggests hashcat/john format.

---

## dast

### zap-scan

```bash
opensec dast zap-scan <target>
```

---

## workflow

### run

```bash
opensec workflow run <file> --target <target>
```

| Arg | Required | Description |
|-----|----------|-------------|
| `file` | yes | Path to workflow YAML file |
| `--target` | yes | Target value injected as `{{ target }}` |

---

## Pipe support

All commands accept stdin input, compatible with ProjectDiscovery ecosystem:

```bash
subfinder -d target.com -silent | opensec enrichment domain-enrich --json
cat ips.txt | opensec abuseipdb ip-check --json
echo "CVE-2024-3094" | opensec nvd cve-get --json
```
