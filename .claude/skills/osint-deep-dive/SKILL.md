---
name: osint-deep-dive
description: >
  Trigger when user asks to "OSINT this target", "gather intelligence on",
  "find everything about this domain", "reconnaissance deep dive",
  "digital footprint analysis", "what's publicly exposed", "full recon on",
  "enumerate everything about", "deep reconnaissance", "passive intelligence
  gathering". Use for comprehensive open-source intelligence gathering
  combining subdomain enumeration, email harvesting, DNS resolution,
  archived URL discovery, technology fingerprinting, and threat enrichment.
---

# OSINT Deep Dive --- Comprehensive Intelligence Gathering

Orchestrate a multi-phase open-source intelligence operation using OpenSecCLI
adapters. Combines subdomain enumeration, email/credential harvesting, DNS
resolution, historical URL discovery, technology fingerprinting, and
multi-source enrichment into a unified intelligence report.

## Required Input

| Parameter | Required | Description |
|-----------|----------|-------------|
| `DOMAIN`  | Yes      | Target domain (e.g., `example.com`) |

Extract the root registrable domain from user input. Strip protocol, paths,
and ports. If a URL is provided, derive the domain. Set `URL` to
`https://$DOMAIN` for tools that require a full URL.

---

## Workflow

### Phase 1 --- Subdomain & Asset Enumeration (run in parallel)

Launch all three commands simultaneously:

```bash
opensec recon subdomain-enum --domain $DOMAIN --format json
```

```bash
opensec recon osint-harvest --domain $DOMAIN --format json
```

```bash
opensec recon dns-resolve --target $DOMAIN --format json
```

From the results, extract:
- **Subdomains**: Deduplicated list from all sources. Flag internal/private IP
  resolutions (10.x, 172.16-31.x, 192.168.x) as information leakage.
- **Email addresses**: Harvested emails, noting role-based (admin@, info@) vs.
  personal addresses. Flag any found in breach databases.
- **DNS records**: A, AAAA, CNAME, MX, NS, TXT, SOA records. Note SPF, DKIM,
  DMARC configuration for email security posture.
- **Hosts/IPs**: Resolved IP addresses for the domain and key subdomains.

### Phase 2 --- Historical & Archived Intelligence (run in parallel)

Launch both commands simultaneously:

```bash
opensec recon url-archive --domain $DOMAIN --format json
```

```bash
opensec recon wayback-urls --domain $DOMAIN --format json
```

From the results, extract:
- **Archived URLs**: Deduplicated historical URLs from web archives.
- **Interesting paths**: Filter for sensitive patterns:
  - Admin panels: `/admin`, `/wp-admin`, `/dashboard`, `/manage`
  - Config files: `/.env`, `/config.json`, `/web.config`, `/.git`
  - API endpoints: `/api/`, `/graphql`, `/swagger`, `/openapi`
  - Backup files: `*.bak`, `*.sql`, `*.dump`, `*.old`, `*.zip`
  - Debug endpoints: `/debug`, `/phpinfo`, `/trace`, `/actuator`
  - Auth pages: `/login`, `/oauth`, `/sso`, `/auth`
- **URL parameter patterns**: Unique parameter names that may indicate
  attack surface (e.g., `?id=`, `?file=`, `?url=`, `?redirect=`).
- **Technology hints**: File extensions and paths indicating tech stack.

### Phase 3 --- Technology & Infrastructure Profiling (run in parallel)

Launch both commands simultaneously:

```bash
opensec recon tech-fingerprint --target https://$DOMAIN --format json
```

```bash
opensec enrichment domain-enrich --domain $DOMAIN --format json
```

From the results, extract:
- **Technology stack**: Web server, frameworks, languages, CMS, JavaScript
  libraries, CDN, WAF, analytics, tag managers.
- **Domain enrichment**: WHOIS data, registrar, creation/expiry dates,
  reputation scores, threat feed matches, SSL certificate details.

### Phase 4 --- Infrastructure Intelligence

Resolve the primary domain IP(s), then query Shodan:

```bash
opensec shodan host-lookup --ip $IP --format json
```

Run for up to 5 unique IPs resolved from the domain and key subdomains.
Launch lookups in parallel via separate Bash calls.

From the results, extract:
- **Open ports and services**: Port, protocol, service name, version, banner.
- **Vulnerabilities**: CVEs associated with running services.
- **SSL/TLS details**: Certificate issuer, validity, protocol versions.
- **Hosting info**: Organization, ASN, country, cloud provider indicators.

---

## Error Handling

- If any `opensec` command fails (non-zero exit, timeout, missing API key),
  log the error, mark that source as `Skipped`, and continue.
- If ALL commands in a phase fail, note the phase as unavailable and suggest
  the user verify configuration with `opensec config show`.
- Never let a single failed step abort the intelligence gathering.
- Parse JSON output safely. Non-JSON output is treated as errored.

---

## Output --- OSINT Intelligence Report

### 1. Target Overview

```
Target Domain:     $DOMAIN
Primary URL:       https://$DOMAIN
Assessment Date:   <current date>
Sources Queried:   <count> of <total>
Sources Skipped:   <list or "None">
```

One-paragraph intelligence summary: overall exposure level, notable findings,
and risk indicators.

### 2. Subdomain Inventory

Table with columns: #, Subdomain, IP Address, Category (Web/Mail/API/Infra/Non-prod), Notes.
Flag subdomains resolving to private IPs or non-production environments.
Include total count and category breakdown.

### 3. Email & Identity Exposure

Table with columns: #, Email, Source, Type (Role-based/Personal), Breach Exposure.
Note email naming conventions for potential username enumeration.

### 4. Infrastructure Map

Table with columns: IP, Hostnames, ASN, Org, Country, Open Ports, Notable Services.
Flag: database ports exposed, admin interfaces on public IPs, outdated
software with known CVEs, unencrypted services (FTP, Telnet).

### 5. Technology Profile

Table with: Web Server, Framework, CMS, CDN/WAF, Analytics, Hosting.

### 6. Archived & Historical URLs

Total count, then table of sensitive paths found (URL Pattern, Category, Risk).
List unique GET parameter patterns indicating attack surface.

### 7. Domain & Threat Intelligence

Table with: Registrar, Created, Expires, Reputation, Threat Feeds,
SPF/DMARC/DKIM status.

### 8. Risk Assessment & Recommended Actions

Findings grouped by severity (Critical/High/Medium/Low) with counts.
Prioritized action table: #, Action, Priority (P0-P3), Finding Reference.

---

## Follow-up Suggestions

After presenting the report, offer relevant next steps:

- "Want me to scan specific subdomains for vulnerabilities?"
- "I can check the discovered emails against breach databases."
- "Should I run a web pentest on any of the discovered endpoints?"
- "I can investigate the archived sensitive paths to see if they are still live."
- "Want me to check the exposed services for known CVEs?"
