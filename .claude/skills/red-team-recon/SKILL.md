---
name: red-team-recon
description: >
  Trigger when user asks to "red team this target", "full recon", "attack surface
  enumeration", "external security assessment", "find attack paths", "adversary
  simulation recon". Use for systematic external reconnaissance following red team
  methodology.
---

# Red Team Recon Skill

Perform systematic external reconnaissance following red team methodology using
OpenSecCLI. Progressively enumerate assets, map infrastructure, fingerprint
technologies, and identify vulnerability surfaces to build an attack path map.

## Authorization Warning

**IMPORTANT**: This skill performs active reconnaissance against external targets.
Ensure you have explicit written authorization before proceeding. Unauthorized
scanning may violate laws (CFAA, Computer Misuse Act, etc.) and terms of service.
Confirm authorization with the user before running any commands.

## Required Input

- **Target** (`$DOMAIN` or `$TARGET`): Domain name, IP address, or URL.

Extract the domain from the user's message. Strip protocol prefixes and paths.
If the user provides a URL, derive the domain for subdomain enumeration and
use the full URL for web-level scanning.

## Phase 1 -- Passive Recon (run all in parallel)

Launch all four commands simultaneously:

```bash
opensec recon subdomain-enum --domain $DOMAIN --format json
```

```bash
opensec recon osint-harvest --domain $DOMAIN --format json
```

```bash
opensec recon url-archive --domain $DOMAIN --format json
```

```bash
opensec recon wayback-urls --domain $DOMAIN --format json
```

- `subdomain-enum`: Passive subdomain enumeration via multiple sources.
- `osint-harvest`: Harvest emails, names, hosts, and metadata from public sources.
- `url-archive`: Retrieve archived URLs from web archives.
- `wayback-urls`: Fetch historical URLs from the Wayback Machine.

Deduplicate all discovered subdomains and URLs. Build the initial asset inventory.

## Phase 2 -- DNS and Infrastructure

Using the discovered subdomains from Phase 1:

```bash
opensec recon dns-resolve --target <comma-separated-subdomains> --format json
```

Filter to live hosts. Then fingerprint technologies on live hosts (batch up to
20 targets):

```bash
opensec recon tech-fingerprint --target <comma-separated-live-hosts> --format json
```

Map: subdomain -> IP -> technology stack. Note shared infrastructure (CDNs,
cloud providers, load balancers).

## Phase 3 -- Active Recon

Run port scanning and web discovery. Choose scan type based on scope:

```bash
opensec recon port-scan --target $TARGET --format json
```

For broad scope, use fast-scan instead:

```bash
opensec recon fast-scan --target $TARGET --format json
```

Run web discovery in parallel on live web targets:

```bash
opensec recon url-crawl --url $URL --format json
```

```bash
opensec recon web-spider --url $URL --format json
```

```bash
opensec recon param-discover --url $URL --format json
```

```bash
opensec recon content-discover --url $URL --format json
```

- `url-crawl` (katana): JavaScript-aware crawling for modern SPAs.
- `web-spider` (gospider): Traditional spidering for link and form discovery.
- `param-discover` (Arjun): Hidden parameter discovery on endpoints.
- `content-discover`: Directory and file brute-forcing for hidden content.

Limit active scanning to the top 5 most interesting hosts (admin panels, APIs,
non-production environments).

## Phase 4 -- Vulnerability Surface

Run vulnerability checks on discovered targets in parallel:

```bash
opensec vuln nuclei-scan --target $URL --format json
```

```bash
opensec vuln xss-scan --url $URL --format json
```

```bash
opensec vuln header-audit --url $URL --format json
```

```bash
opensec vuln cors-check --url $URL --format json
```

- `nuclei-scan`: Template-based vulnerability detection (CVEs, misconfigs,
  exposures, default credentials).
- `xss-scan`: Reflected and DOM-based XSS detection.
- `header-audit`: Missing or misconfigured security headers.
- `cors-check`: CORS misconfiguration allowing credential theft.

## Error Handling

- If a command fails (non-zero exit, timeout, missing tool), mark that phase
  as `unavailable` in the report. Do NOT stop the recon.
- If a tool requires an API key that is missing, note the skip and continue.
- If ALL commands fail, suggest checking `opensec --version` and tool
  installation status.
- Never let a single failed step abort the entire assessment.

## Output -- Red Team Recon Report

Present findings in this structure:

```markdown
# Red Team Recon Report

**Target:** `$DOMAIN`
**Assessment Date:** <current date/time>
**Authorization:** Confirmed by operator

---

## Attack Surface Summary

| Category | Count |
|----------|-------|
| Subdomains discovered | X |
| Live hosts | X |
| Open ports | X |
| Web applications | X |
| Parameters discovered | X |
| Vulnerabilities found | X |

---

## Asset Inventory

### Subdomains & DNS

| Subdomain | IP | Status | Notes |
|-----------|----|--------|-------|
| app.example.com | 1.2.3.4 | Live | Main application |
| dev.example.com | 5.6.7.8 | Live | Non-production |

### Technology Stack

| Host | Technologies | Server | Frameworks |
|------|-------------|--------|------------|
| app.example.com | React, Node.js | nginx/1.24 | Express |

### Open Ports & Services

| Host | Port | Service | Version | Risk |
|------|------|---------|---------|------|
| 1.2.3.4 | 443 | HTTPS | nginx/1.24 | Low |
| 5.6.7.8 | 3306 | MySQL | 8.0.32 | Critical |

---

## Discovered Endpoints

List interesting URLs from crawling/spidering, hidden parameters from Arjun,
and archived content from Wayback that is still live.

---

## Vulnerability Findings

| # | Host | Finding | Severity | Type | Details |
|---|------|---------|----------|------|---------|
| 1 | app.example.com | SQL Injection | Critical | SQLi | /api/search?q= |
| 2 | dev.example.com | Missing HSTS | Medium | Header | No Strict-Transport-Security |

---

## Prioritized Attack Paths

### Path 1: <Name> (Severity: Critical)
1. Entry point: <description>
2. Exploitation: <technique>
3. Impact: <what attacker gains>

### Path 2: <Name> (Severity: High)
1. Entry point: <description>
2. Exploitation: <technique>
3. Impact: <what attacker gains>

---

## OSINT Intelligence

- **Emails discovered:** X
- **Employee names:** X
- **Leaked credentials:** check against known breach databases
- **Metadata findings:** document properties, server headers

---

## Recommendations

### Immediate Actions
1. <Close critical attack paths>
2. <Patch exploitable vulnerabilities>

### Hardening
1. <Remove non-production from public access>
2. <Implement missing security headers>
3. <Restrict CORS policies>

### Monitoring
1. <Set up alerts for discovered attack surfaces>
```

## Follow-up Suggestions

After presenting the report, offer relevant next steps such as deep-diving into
a specific attack path, running focused vulnerability scans on particular hosts,
checking credentials against breach databases, or testing parameters for injection.
