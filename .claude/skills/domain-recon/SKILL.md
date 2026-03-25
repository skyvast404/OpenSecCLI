---
name: domain-recon
description: >
  Should trigger when user asks to "recon a domain", "find subdomains",
  "domain reconnaissance", "asset discovery for", "what do we know about
  this domain", "enumerate subdomains", "check domain exposure". Also
  trigger for "OSINT on domain", "domain intelligence", or when user
  provides a domain name and wants comprehensive information about it.
---

# Domain Reconnaissance & Asset Discovery

Perform comprehensive domain reconnaissance using OpenSecCLI adapters to
enumerate subdomains, map infrastructure, identify exposed services, and
check threat intelligence feeds.

## Required Input

- `DOMAIN` — the target domain (e.g., `example.com`)

Extract the domain from the user's message. Strip any protocol prefix
(`https://`), trailing paths, or port numbers. If the user provides a
subdomain like `app.example.com`, use the root registrable domain for
cert transparency and VirusTotal, but include the exact input in Shodan
and threat feed checks.

## Workflow

### Phase 1 — Passive Discovery (run in parallel)

Launch both commands simultaneously:

```bash
opensec crtsh cert-search --domain $DOMAIN --format json
```

```bash
opensec virustotal domain-lookup --domain $DOMAIN --format json
```

- **crtsh**: Collect all subdomains from certificate transparency logs.
  Deduplicate and remove wildcard entries (`*.example.com`).
- **VirusTotal**: Capture reputation verdict, last analysis stats,
  categories, registrar, creation date, and any detection flags.

If VirusTotal fails (no API key), note it and continue — crtsh requires
no key.

### Phase 2 — DNS Resolution

Resolve the primary domain and up to 10 interesting subdomains to IP
addresses:

```bash
dig +short $DOMAIN A
dig +short $SUBDOMAIN A
```

Select "interesting" subdomains by prioritizing:
1. mail / mx / smtp — mail infrastructure
2. vpn / remote / gateway — remote access
3. admin / portal / manage / dashboard — admin panels
4. api / graphql / ws — API endpoints
5. dev / staging / test / uat — non-production environments
6. db / sql / mongo / redis — database endpoints (high risk if exposed)
7. Any subdomain with an unusual or unique name

Collect the unique set of resolved IPs.

### Phase 3 — Infrastructure & Threat Intel (run in parallel where possible)

**3a. Shodan host lookup** — up to 5 IPs (prioritize IPs hosting
interesting subdomains):

```bash
opensec shodan host-lookup --ip $IP --format json
```

Capture: open ports, services/banners, OS, vulns, last update.

**3b. IP geolocation & ASN** — primary domain IP:

```bash
opensec ipinfo ip-lookup --ip $PRIMARY_IP --format json
```

Capture: country, city, org, ASN, anycast status.

**3c. ThreatFox IOC check** — domain and key subdomains:

```bash
opensec abuse.ch threatfox-search --ioc $DOMAIN --format json
```

Capture: any IOC matches, malware family, threat type, confidence.

**3d. URLhaus check** — primary domain URL:

```bash
opensec abuse.ch urlhaus-query --url "https://$DOMAIN" --format json
opensec abuse.ch urlhaus-query --url "http://$DOMAIN" --format json
```

Capture: any malware distribution URLs, payload info, tags.

Run 3a-3d in parallel. If a command fails due to missing API key or
rate limit, log the skip and continue with remaining sources.

## Output — Domain Intelligence Report

Present findings as a structured report with these sections:

### 1. Domain Overview

| Field | Value |
|-------|-------|
| Target | `$DOMAIN` |
| Registrar | from VirusTotal |
| Creation Date | from VirusTotal |
| Reputation | VirusTotal verdict (malicious/clean/unrated) |
| Detection Ratio | `X/Y engines flagged as malicious` |
| Categories | from VirusTotal |

### 2. Subdomains Found

List all unique subdomains from crtsh, grouped by function:

- **Web**: www, app, portal, ...
- **Mail**: mail, smtp, mx, ...
- **API**: api, graphql, ...
- **Infrastructure**: vpn, gateway, ns1, ...
- **Non-production**: dev, staging, test, ...
- **Other**: everything else

Include total count. Flag any subdomains pointing to internal/private
IPs (10.x, 172.16-31.x, 192.168.x) — this can indicate DNS
misconfiguration or information leakage.

### 3. Infrastructure

| IP | Hostname(s) | ASN | Org | Country | City |
|----|-------------|-----|-----|---------|------|

Note if multiple subdomains resolve to the same IP (shared hosting or
CDN). Note if IPs span multiple ASNs or countries.

### 4. Exposed Services

For each Shodan result:

| IP | Port | Service | Version | Notes |
|----|------|---------|---------|-------|

Flag these as high-risk findings:
- Database ports open to internet (3306, 5432, 27017, 6379)
- Admin panels on public IPs (port 8080, 8443, 9090, etc.)
- Outdated software versions with known CVEs
- Telnet (23), FTP (21), or other unencrypted services
- RDP (3389) or SSH (22) on non-standard hosts
- Self-signed or expired TLS certificates

### 5. Threat Intelligence

| Source | Status | Finding |
|--------|--------|---------|
| VirusTotal | clean/malicious/not checked | detection details |
| ThreatFox | found/not found/not checked | IOC details if found |
| URLhaus | found/not found/not checked | malware URL details if found |

If any threat feed returns a hit, mark this section with a warning.

### 6. Risk Assessment

Summarize findings into risk categories:

- **CRITICAL**: Domain flagged as malicious in threat feeds, known IOC
  associations, active malware distribution
- **HIGH**: Database ports exposed, admin panels public, outdated
  services with known CVEs, private IPs in DNS
- **MEDIUM**: Non-production environments exposed, unencrypted services,
  large attack surface (many subdomains)
- **LOW**: Standard web hosting, no concerning findings
- **INFO**: Observations that are not risks but worth noting

Provide 2-3 sentences of overall assessment and recommended next steps.

## Error Handling

- If `opensec` is not installed or not in PATH, tell the user to install
  it: `npm install -g opensec-cli`
- If an API key is missing for a provider, note which checks were skipped
  and suggest: `opensec auth add <provider> --api-key`
- If crtsh returns no results, the domain may be new or using private CA
  — note this and continue with other checks
- If dig/nslookup is unavailable, try the other; if both fail, skip DNS
  resolution and note it
- Never let a single failed step abort the entire recon — always produce
  a partial report with whatever data was collected

## Example Invocation

User: "recon example.com"

The skill should:
1. Run crtsh + VirusTotal in parallel
2. Resolve discovered subdomains via dig
3. Run Shodan, ipinfo, ThreatFox, URLhaus in parallel
4. Compile and present the Domain Intelligence Report
