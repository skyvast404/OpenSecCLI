---
name: attack-surface-map
description: >
  Trigger when user asks to "map attack surface", "find exposed endpoints",
  "what's our exposure", "enumerate entry points", "security surface analysis",
  "what services are exposed", "external attack surface", "EASM",
  "asset discovery", or wants to understand all the ways an application
  can be attacked.
---

# Attack Surface Map

Map the full attack surface of an application from both internal (code) and
external (network exposure) perspectives. Produce a risk-rated report of every
entry point.

## Inputs

| Parameter | Required | Description |
|-----------|----------|-------------|
| `path`    | Yes      | Path to the project root |
| `ip`      | No       | Host IP for external surface analysis |
| `domain`  | No       | Domain for cert/subdomain/reputation checks |

If the user does not provide `path`, ask for it. If neither `ip` nor `domain`
is provided, skip external surface analysis and note that in the report.

---

## Workflow

### Phase 1 — Internal Surface Discovery

Run the following two commands in parallel:

```bash
opensec scan discover --path <path> --format json
opensec scan entrypoints --path <path> --format json
```

From the output, extract:
- Languages and frameworks detected
- Every HTTP route, RPC handler, WebSocket endpoint, GraphQL resolver,
  message queue consumer, and cron/scheduled task
- For each entry point, note: method, path/pattern, handler function,
  source file, and line number

Then run static analysis to find security-sensitive code paths:

```bash
opensec scan analyze --path <path> --format json
```

Extract findings related to:
- Authentication/authorization checks (or lack thereof)
- Input validation and deserialization
- File upload handlers
- Database query construction (SQL injection surface)
- Command execution / subprocess calls
- Cryptographic operations
- Secret/credential handling

Optionally, gather git-based security signals:

```bash
opensec scan git-signals --path <path> --format json
```

Look for:
- Recently changed auth or security-critical files
- Commits that disabled security controls
- Large diffs to sensitive areas (rushed changes)

### Phase 2 — External Surface Discovery (Optional)

Only execute if user provides `ip` or `domain`. Run applicable commands
in parallel:

```bash
# If ip is provided
opensec shodan host-lookup --ip <ip> --format json

# If domain is provided
opensec crtsh cert-search --domain <domain> --format json
opensec virustotal domain-lookup --domain <domain> --format json
```

From the output, extract:
- Open ports and services (Shodan)
- TLS certificate details and expiry
- Subdomains discovered via certificate transparency
- Domain reputation and any malicious indicators
- Exposed admin panels, debug endpoints, or dev services

### Phase 3 — Risk Assessment

Classify every discovered entry point into a risk tier:

| Risk Level | Criteria | Examples |
|------------|----------|----------|
| **Critical** | Unprotected + handles sensitive data | Unauthenticated admin API, open DB port |
| **High** | No authentication or exposed externally without auth | Public API without auth, open SSH |
| **Medium** | Auth-protected but externally reachable | Authenticated REST endpoints on public IP |
| **Low** | Internal-only or defense-in-depth present | Internal microservice RPC, health checks |
| **Info** | No direct risk but worth documenting | Static asset routes, version endpoints |

For each entry point, determine:
1. **Authentication status** — Does the handler check auth? (trace middleware chain)
2. **Authorization scope** — Any role/permission guards?
3. **Input surface** — What user-controlled data does it accept?
4. **External reachability** — Is it exposed beyond localhost/VPN?
5. **Data sensitivity** — Does it touch PII, credentials, or financial data?

### Phase 4 — Report Generation

Produce the final Attack Surface Report in markdown with these sections:

#### 4.1 Summary Stats

```
Total entry points found: <N>
  Critical risk: <n>
  High risk:     <n>
  Medium risk:   <n>
  Low risk:      <n>
  Info:          <n>

Frameworks detected: <list>
External services exposed: <n> (or "N/A — no IP/domain provided")
```

#### 4.2 Internal Entry Points

Group by framework or protocol. For each entry point, render a table:

| Method | Path / Pattern | Auth | Risk | Handler | File:Line |
|--------|---------------|------|------|---------|-----------|
| GET    | /api/users    | None | High | getUsers | src/routes/users.ts:42 |
| POST   | /api/login    | N/A  | Medium | login | src/routes/auth.ts:15 |

Include a subsection for **Security-Sensitive Code Paths** listing:
- Unvalidated input handlers
- Raw SQL or command execution
- Disabled security controls found in git history

#### 4.3 External Exposure (if applicable)

| Asset | Port/Service | Details | Risk |
|-------|-------------|---------|------|
| 203.0.113.5 | 443/HTTPS | TLS 1.2, cert expires 2026-09 | Medium |
| 203.0.113.5 | 22/SSH | OpenSSH 8.9 | High |

Subdomains discovered:
- `api.example.com` — resolves to 203.0.113.5
- `staging.example.com` — resolves to 203.0.113.10

If no IP/domain was provided, print:
> External surface analysis was skipped. Provide `--ip` or `--domain` to
> include Shodan, certificate transparency, and domain reputation checks.

#### 4.4 Risk Matrix

A condensed view crossing entry points against risk factors:

| Entry Point | Auth | External | Sensitive Data | Input Complexity | Overall Risk |
|-------------|------|----------|---------------|-----------------|-------------|
| POST /api/upload | Yes | Yes | No | High (file) | Medium |
| GET /admin | No | Yes | Yes | Low | Critical |

#### 4.5 Recommendations

Provide actionable recommendations ordered by risk:
1. **Critical/High** — specific remediation steps (add auth middleware, restrict port, etc.)
2. **Medium** — hardening suggestions (rate limiting, input validation, TLS upgrade)
3. **General** — security posture improvements (enable HSTS, remove debug endpoints)

---

## Error Handling

- If any `opensec` command fails, log the error, continue with remaining
  commands, and note the gap in the report under a **Data Gaps** section.
- If the project path is invalid, stop and ask the user for a valid path.
- If Shodan/crtsh/VirusTotal returns empty results, note "No data returned"
  rather than omitting the section.

## Output Format

- Default: Markdown report printed to stdout.
- If user asks for JSON, structure the output as:
  ```json
  {
    "summary": { "total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0 },
    "internal_surface": { "frameworks": [], "entry_points": [], "sensitive_paths": [] },
    "external_surface": { "ports": [], "subdomains": [], "certificates": [] },
    "risk_matrix": [],
    "recommendations": []
  }
  ```

## Example Invocation

User: "Map the attack surface of this project"
→ Ask for path if not obvious from context. Run Phase 1 only.

User: "Map attack surface for ./myapp, domain is api.example.com, IP is 203.0.113.5"
→ Run all four phases.

User: "What endpoints are exposed on api.example.com?"
→ Run Phase 2 (external) with domain. Skip internal unless path is provided.
