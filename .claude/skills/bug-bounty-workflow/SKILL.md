---
name: bug-bounty-workflow
description: >
  Trigger when user asks about "bug bounty", "find bugs for bounty", "bounty
  hunting methodology", "HackerOne target", "Bugcrowd testing", "vulnerability
  reward program". Use for structured bug bounty hunting workflow optimized for
  finding reportable vulnerabilities.
---

# Bug Bounty Workflow Skill

Execute a structured bug bounty hunting workflow using OpenSecCLI, optimized for
finding reportable vulnerabilities efficiently. Follows a methodology that
prioritizes quick wins before deep testing.

## Responsible Disclosure Notice

**IMPORTANT**: Only test targets you are authorized to test. Ensure the target
is within an active bug bounty program scope (HackerOne, Bugcrowd, Intigriti,
or private program). Respect program rules: rate limits, out-of-scope areas,
and disclosure timelines. Never access, modify, or exfiltrate real user data.

## Required Input

- **Target domain** (`$DOMAIN`): The in-scope domain to test.
- **Program scope** (optional): In-scope/out-of-scope domains, bounty table,
  and program rules. If provided, enforce scope throughout.

If the user provides a program URL (e.g., HackerOne page), ask them to paste
the scope details. Do not scrape bounty platforms.

## Phase 1 -- Scope Analysis

Parse the program scope if provided:
- List in-scope domains and wildcards
- Note out-of-scope domains and endpoints
- Identify bounty table (severity -> reward mapping)
- Note special rules (no automated scanning, rate limits, etc.)

If no scope is provided, treat the given domain as in-scope and warn:
"No program scope provided. Treating `$DOMAIN` as in-scope. Please confirm
this target is part of an active bounty program."

## Phase 2 -- Asset Discovery (run in parallel)

```bash
opensec recon subdomain-enum --domain $DOMAIN --format json
```

```bash
opensec recon url-archive --domain $DOMAIN --format json
```

```bash
opensec recon dns-resolve --target <discovered-subdomains> --format json
```

Run subdomain-enum and url-archive in parallel. Then resolve discovered
subdomains to filter to live hosts. Remove any out-of-scope assets.

Build asset list: subdomain -> IP -> live status.

## Phase 3 -- Tech Profiling

On live in-scope hosts:

```bash
opensec recon tech-fingerprint --target $URL --format json
```

```bash
opensec recon url-crawl --url $URL --format json
```

- Identify technology stacks (frameworks, CMSes, WAFs).
- Crawl for endpoints, forms, API routes, and JavaScript files.
- Note technology-specific attack vectors (e.g., WordPress -> WPScan,
  GraphQL -> introspection, JWT -> algorithm confusion).

## Phase 4 -- Quick Wins (run all in parallel)

These target the most common bounty-eligible findings:

```bash
opensec vuln header-audit --url $URL --format json
```

```bash
opensec vuln cors-check --url $URL --format json
```

```bash
opensec vuln xss-scan --url $URL --format json
```

```bash
opensec vuln crlf-scan --url $URL --format json
```

```bash
opensec pentest jwt-test --token $JWT --format json
```

- `header-audit`: Missing security headers (CSP, HSTS, X-Frame-Options).
  Bounty eligibility varies; some programs accept, others do not.
- `cors-check`: CORS misconfiguration allowing credential theft. Often
  P2-P3 severity on bounty platforms.
- `xss-scan`: Reflected XSS via parameter fuzzing. High-value finding.
- `crlf-scan`: CRLF injection leading to header injection or response
  splitting. Medium-value finding.
- `jwt-test`: JWT algorithm confusion, weak signing, missing validation.
  Only run if a JWT token is available (from cookies, auth headers).

Skip `jwt-test` if no JWT is available. Run the others on all live web targets
(limit to top 10 hosts).

## Phase 5 -- Deep Testing

Based on Phase 3 tech profiling and Phase 4 results, perform targeted testing:

```bash
opensec recon param-discover --url $URL --format json
```

Discover hidden parameters on interesting endpoints. Then fuzz discovered
parameters:

```bash
opensec pentest fuzz --url $URL --payloads sqli,xss,ssrf --format json
```

```bash
opensec pentest sqli-scan --url $URL --format json
```

- `param-discover`: Find hidden/undocumented parameters (debug, admin, internal).
- `fuzz`: Payload-based fuzzing for SQLi, XSS, and SSRF on discovered params.
- `sqli-scan`: Dedicated SQL injection testing with advanced techniques.

Focus deep testing on:
1. Endpoints with user input (search, login, API params)
2. Authenticated endpoints if credentials are available
3. File upload functionality
4. Password reset flows
5. API endpoints with complex input

## Error Handling

- If a command fails, mark it as `unavailable` and continue.
- If a tool is rate-limited, note it and suggest retrying later.
- Respect any rate-limit headers in responses.
- Never let a single failed step abort the workflow.

## Bounty-Relevant Severity Mapping

| Finding Type | Typical Platform Severity | Notes |
|-------------|--------------------------|-------|
| RCE, SQLi with data access | P1 / Critical | Highest reward tier |
| Stored XSS, SSRF to internal | P2 / High | Strong bounty candidates |
| Reflected XSS, CORS with creds | P2-P3 / High-Medium | Confirm exploitability |
| CRLF injection, open redirect | P3-P4 / Medium-Low | Program-dependent |
| Missing headers (no impact) | P4-P5 / Low-Info | Often out of scope |
| JWT algo confusion (exploitable) | P2 / High | Requires PoC |

## Output -- Bug Bounty Report

For each confirmed finding, generate a report template:

```markdown
# Bug Bounty Findings Report

**Target Program:** <program name if known>
**Domain:** `$DOMAIN`
**Tested:** <current date/time>
**Tester:** <user>

---

## Findings Summary

| # | Title | Severity | Endpoint | Bounty Eligible |
|---|-------|----------|----------|-----------------|
| 1 | Reflected XSS in search | P2 High | /search?q= | Yes |
| 2 | CORS misconfiguration | P3 Medium | /api/user | Yes |
| 3 | Missing CSP header | P5 Info | / | Unlikely |

---

## Finding 1: <Title>

### Severity
P2 / High

### Endpoint
`https://example.com/search?q=<payload>`

### Description
<Clear description of the vulnerability, what it is, and why it matters.>

### Steps to Reproduce
1. Navigate to `https://example.com/search`
2. Enter the following payload in the search field: `<payload>`
3. Observe <behavior>
4. ...

### Impact
<What can an attacker do? Data theft, account takeover, etc.>

### Proof of Concept
<Include exact request/response, screenshot description, or script.>

```http
GET /search?q=<script>alert(document.domain)</script> HTTP/1.1
Host: example.com
```

### Remediation
<Specific fix recommendation.>

---

## Assets Discovered (for future testing)

### Subdomains: X total, Y live
### Endpoints crawled: X
### Parameters discovered: X
### Technologies: <stack summary>
```

## Follow-up Suggestions

After presenting findings, suggest:

- "Want me to craft a detailed submission-ready report for a specific finding?"
- "Should I test additional subdomains or endpoints?"
- "I can attempt to chain findings for higher impact (e.g., XSS + CORS)."
- "Want me to verify if a finding is a duplicate by checking common patterns?"

Offer these only when findings warrant follow-up.
