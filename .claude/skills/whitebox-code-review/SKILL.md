---
name: whitebox-code-review
description: >
  Trigger when user asks to "review this code for security", "white-box audit",
  "source code security review", "find vulnerabilities in this codebase",
  "taint analysis", "SAST review", "code audit for injection/XSS". Use for
  systematic source code security review using backward taint analysis methodology.
---

# White-Box Code Security Review

Deep source code security review combining automated tooling with manual backward
taint analysis. Goes beyond `code-security-audit` by classifying every injection
sink and XSS output context, performing auth/authz review, and producing a
priority-ordered exploitation queue.

> **AUTHORIZATION WARNING**: Before proceeding, confirm with the user that they
> have explicit written authorization to audit this codebase. Reviewing code you
> do not own or have permission to audit may violate agreements, laws, or
> regulations. If the user cannot confirm authorization, do NOT proceed.

## Inputs

| Parameter | Required | Description |
|-----------|----------|-------------|
| `PATH`    | Yes      | Absolute path to the codebase root |

If the user says "review this code" without a path, use the current working directory.

---

## Workflow

### Phase 1 --- Automated Discovery (run all four in parallel)

```bash
opensec scan discover --path $PATH --format json
```

```bash
opensec scan entrypoints --path $PATH --format json
```

```bash
opensec scan analyze --path $PATH --format json
```

```bash
opensec scan git-signals --path $PATH --format json
```

From the combined results, extract:
- Languages, frameworks, package managers, project size
- Every HTTP route, handler function, file, line, middleware chain
- Semgrep findings, gitleaks secrets, dependency audit results
- Security-relevant commits (fix, vuln, CVE, patch, secret keywords)

Summarize to the user before continuing:
> "Discovered a [language]/[framework] project with [N] entry points and [M]
> automated findings. Starting manual taint analysis..."

### Phase 2 --- Manual Taint Analysis

For **each entry point** found in Phase 1, trace data flow: **source -> processing -> sink**.

#### 2a. Injection Sink Classification

For every data path that reaches a dangerous sink, classify by **Slot Type**:

| Slot Type | Sink Pattern | Example Vulnerable Code | Risk |
|-----------|-------------|------------------------|------|
| SQL-val | String concat/interp in SQL value position | `WHERE id = '${input}'` | SQLi (value escape bypass) |
| SQL-ident | User input in table/column name | `ORDER BY ${column}` | SQLi (identifier injection) |
| CMD-argument | User input in shell command | `exec('nmap ' + host)` | OS command injection |
| CMD-full | User input as entire command | `exec(userInput)` | Full RCE |
| FILE-path | User input in file path | `readFile('/uploads/' + name)` | Path traversal / LFI |
| FILE-content | User input written to file | `writeFile(path, userBody)` | Arbitrary file write |
| TEMPLATE-expr | User input in template engine | `render('Hello #{name}')` | SSTI / RCE |
| DESERIAL | User input deserialized | `JSON.parse(body)`, `pickle.loads(data)` | Insecure deserialization |
| LDAP-filter | User input in LDAP query | `(&(uid=${input}))` | LDAP injection |
| XPATH-expr | User input in XPath | `//user[@id='${input}']` | XPath injection |

For each finding record: entry point, source parameter, transforms applied, sink
location (file:line), slot type, and whether sanitization exists.

#### 2b. XSS Output Context Classification

For every path where user input reaches rendered output, classify by **Render Context**:

| Render Context | Output Location | Required Escaping | Bypass Risk |
|---------------|----------------|-------------------|-------------|
| HTML_BODY | Between HTML tags | HTML entity encoding | Low if encoded |
| HTML_ATTRIBUTE | Inside tag attribute | Attribute encoding + quoting | Medium (quote break) |
| JAVASCRIPT_STRING | Inside JS string literal | JS string escape + CSP | High (string break) |
| JAVASCRIPT_BLOCK | Raw JS execution context | Must not allow; use CSP | Critical |
| URL_PARAM | href/src attribute value | URL encoding + scheme allowlist | High (javascript:) |
| CSS_VALUE | style attribute / stylesheet | CSS encoding + strict validation | Medium |
| JSON_RESPONSE | API JSON body reflected | Content-Type: application/json | Low if typed |

For each finding record: entry point, source parameter, render context,
encoding applied (if any), and whether CSP mitigates.

### Phase 3 --- Authentication & Authorization Review

#### 3a. Authentication Checklist (9 points)

Evaluate each item as PASS, FAIL, or N/A:

| # | Check | What to Look For |
|---|-------|-----------------|
| 1 | Transport security | All auth endpoints over HTTPS; no credentials in query strings |
| 2 | Rate limiting | Login, register, password reset have rate limits or CAPTCHA |
| 3 | Session management | Secure, HttpOnly, SameSite cookies; adequate expiry |
| 4 | Token handling | JWTs validated properly (alg, exp, iss, aud); no `alg:none` |
| 5 | Session fixation | Session ID regenerated after login |
| 6 | Password policy | Minimum length, complexity or zxcvbn, bcrypt/argon2 hashing |
| 7 | Login uniformity | Same response for valid vs invalid usernames (no enumeration) |
| 8 | Recovery flow | Password reset tokens are single-use, time-limited, high entropy |
| 9 | SSO/OAuth | State param present, redirect URI validated, PKCE for public clients |

#### 3b. Authorization Review (3 types)

| Type | Test | Description |
|------|------|-------------|
| Horizontal | Access user A's resource as user B | IDOR checks on all resource endpoints |
| Vertical | Access admin endpoint as regular user | Role escalation across privilege boundaries |
| Context-workflow | Skip step in multi-step process | Access step 3 without completing step 1-2 |

For each entry point, note which authz type is relevant and whether guards exist.

#### 3c. SSRF Sink Hunting

Search for code patterns where user input influences outbound requests:

| SSRF Type | Pattern | Example |
|-----------|---------|---------|
| Classic | Direct URL from user | `fetch(req.body.url)` |
| Blind | URL used server-side, no response returned | `webhook.send(userUrl)` |
| Semi-blind | Partial response info leaked (timing, status) | DNS rebinding via user domain |
| Stored | URL saved then fetched later | Profile avatar URL fetched by background job |

### Phase 4 --- Dependency & Secrets (run in parallel)

```bash
opensec supply-chain dep-audit --path $PATH --format json
```

```bash
opensec secrets trufflehog-scan --path $PATH --format json
```

From the results, extract:
- Vulnerable dependencies: package, version, CVE, severity, fix version
- Exposed secrets: type (API key, password, token), file, line, whether active

### Phase 5 --- Synthesis

#### 5a. Confidence-Scored Findings

Assign each finding a confidence score:

| Score | Meaning | Criteria |
|-------|---------|----------|
| **HIGH** (0.8-1.0) | Very likely exploitable | No sanitization, direct sink, confirmed by tool + manual review |
| **MEDIUM** (0.5-0.79) | Possibly exploitable | Partial sanitization, or tool-only finding not manually verified |
| **LOW** (0.1-0.49) | Needs further investigation | Sanitization present but incomplete, edge-case only |

#### 5b. Exploitation Queue

Produce a priority-ordered list for downstream exploit validation:

```json
[
  {
    "rank": 1,
    "finding_id": "TAINT-001",
    "type": "SQL-val",
    "entry_point": "POST /api/search",
    "source_param": "query (body)",
    "sink": "src/db/search.ts:42",
    "confidence": 0.95,
    "severity": "critical",
    "notes": "No parameterization, raw string concat into pg query"
  }
]
```

---

## Error Handling

- If any `opensec` command fails, log the error, mark that check as `Skipped`
  in the report, and continue. Never abort the entire review.
- If ALL Phase 1 commands fail, suggest `opensec config show` to verify installation.
- Parse JSON output safely. If output is invalid JSON, include raw stderr in a
  **Data Gaps** section.
- If no entry points are found, still perform Phase 4 (dependency/secrets) and
  note limited taint analysis coverage.

---

## Output --- White-Box Security Audit Report

### 1. Executive Summary

```
Target:          $PATH
Date:            <current date>
Authorization:   Confirmed by user
Languages:       <from discover>
Framework:       <from discover>

Total findings:  <N>
  Critical: <n>  |  High: <n>  |  Medium: <n>  |  Low: <n>
```

2-3 sentence summary of overall security posture and top risks.

### 2. Architecture Overview

Languages, frameworks, project structure, and key components from discover output.

### 3. Entry Points Inventory

Table of all routes with method, path, auth status, handler, file:line.

### 4. Taint Analysis Findings

Grouped by slot type / render context. Each finding includes: entry point, source,
transforms, sink location, classification, confidence score, and remediation.

### 5. Auth/Authz Assessment

9-point checklist results table, authz review per entry point, SSRF sinks found.

### 6. Dependency & Secret Risks

Vulnerable dependencies table (package, CVE, severity, fix version).
Exposed secrets table (type, file, line, active status).

### 7. Exploitation Queue

Priority-ordered JSON array of findings ready for exploit validation.

### 8. Remediation Roadmap

| Priority | Finding | Effort | Action |
|----------|---------|--------|--------|
| 1 | SQLi in /api/search | Medium | Parameterized queries |
| 2 | Hardcoded DB password | Low | Move to env/vault |

### 9. Data Gaps

List any skipped checks with reasons and how to enable them.

---

## Follow-up Suggestions

After presenting the report, offer:
- "Want me to validate any of these findings with active exploitation testing?"
- "I can run the exploit-validation skill against the exploitation queue."
- "Should I deep-dive into any specific finding's data flow?"
- "I can generate remediation patches for the critical findings."
