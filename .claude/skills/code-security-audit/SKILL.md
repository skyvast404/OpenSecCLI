---
name: code-security-audit
description: >
  Should trigger when user asks to "audit", "review security", "check for vulnerabilities",
  "scan for security issues", "security assessment" of a codebase or project. Also trigger
  for "is this code secure", "find security bugs", "SAST scan", "static analysis".
  Use this skill whenever the user wants comprehensive security analysis of source code.
---

# Code Security Audit

Orchestrate a full security audit of a codebase using OpenSecCLI tools.

## Inputs

- `TARGET_PATH` — absolute path to the codebase to audit (required; ask user if not provided)
- `OUTPUT_DIR` — directory for reports (default: `<TARGET_PATH>/scan-results`)

If the user says "audit this project" without specifying a path, use the current working directory.

## Workflow

### Step 1: Discovery — Understand the Target

Run project discovery to map languages, frameworks, entry points, and project structure.

```bash
opensec scan discover --path <TARGET_PATH> --format json
```

Parse the JSON output. Extract:
- Languages and their percentages
- Frameworks detected (Express, Django, Spring, etc.)
- Package managers in use
- Project size and file count

Summarize findings to the user before proceeding:
> "This is a [language] project using [framework], with [N] source files. Proceeding with security analysis..."

### Step 2: Static Analysis — Find Vulnerabilities

Run all static analysis tools in parallel.

```bash
opensec scan analyze --path <TARGET_PATH> --format json
```

This runs semgrep rules, gitleaks secret detection, and dependency audits (npm audit / pip audit) under the hood.

Parse the JSON output. For each finding, extract:
- Rule ID and tool source (semgrep, gitleaks, npm-audit, pip-audit)
- Severity (critical, high, medium, low, info)
- File path and line number
- Description and match snippet
- CWE ID if available

### Step 3: Entry Point Mapping — Identify Attack Surface

Map HTTP routes, handlers, and externally reachable endpoints.

```bash
opensec scan entrypoints --path <TARGET_PATH> --format json
```

Parse the JSON output. Extract:
- HTTP method and route pattern
- Handler function and file location
- Authentication/authorization middleware (if detectable)
- Input parameters and their sources (query, body, path, headers)

### Step 4: Git Security Signals — Check History

Extract security-relevant commits and patterns from git history.

```bash
opensec scan git-signals --path <TARGET_PATH> --format json
```

Parse the JSON output. Look for:
- Commits mentioning "fix", "vuln", "CVE", "security", "patch"
- Previously committed secrets that may still be in history
- Large diffs that could indicate hasty fixes
- Recently changed security-critical files

### Step 5: Correlation and Prioritization

This is the critical analysis step. Do NOT skip it.

**Cross-reference findings with entry points:**
- For each vulnerability found in Step 2, check if the affected code is reachable from an entry point found in Step 3.
- A SQL injection in a function called from a public API route is CRITICAL.
- The same SQL injection in dead code or an internal-only admin tool is MEDIUM.

**Severity classification:**

| Priority | Criteria | Examples |
|----------|----------|---------|
| CRITICAL | Exploitable from public entry point, leads to RCE/data breach | SQLi in public API, RCE via deserialization, hardcoded prod secrets |
| HIGH | Exploitable but requires auth, or high-impact with limited reach | XSS in authenticated routes, leaked API keys, known CVE in dependency |
| MEDIUM | Requires specific conditions or has limited impact | CSRF without state-changing actions, info disclosure, outdated deps |
| LOW | Informational or defense-in-depth | Missing security headers, verbose errors in dev mode, code quality |

**For each finding, determine:**
1. Is the vulnerable code reachable from an entry point?
2. What is the blast radius if exploited?
3. Is there existing mitigation (WAF, input validation, auth check)?
4. How easy is it to exploit?

### Step 6: CVE Enrichment (if dependency vulnerabilities found)

For any dependency vulnerabilities found in Step 2, enrich with CVE details:

```bash
opensec nvd cve-search --keyword <package-name>
```

Run this for the top critical/high dependency findings only — do not flood the NVD API.

### Step 7: Generate Report

#### 7a: Save machine-readable report

```bash
opensec scan report --input <analysis-output-file> --output_dir <OUTPUT_DIR>
```

This produces JSON, SARIF, and Markdown files in the output directory.

#### 7b: Present audit report in conversation

Structure the report as follows:

```markdown
# Security Audit Report

**Target:** <TARGET_PATH>
**Date:** <current date>
**Scanner:** OpenSecCLI

## Executive Summary

- **Critical:** N findings
- **High:** N findings
- **Medium:** N findings
- **Low:** N findings
- **Overall Risk:** [Critical | High | Medium | Low]

Brief 2-3 sentence summary of the most important findings and overall security posture.

## Attack Surface

Summary of entry points found. Note which are authenticated vs public.

| Route | Method | Auth Required | Risk Notes |
|-------|--------|---------------|------------|
| /api/login | POST | No | Input validation needed |
| ... | ... | ... | ... |

## Critical & High Findings

### [Finding Title] — CRITICAL

- **Tool:** semgrep / gitleaks / npm-audit
- **Location:** `src/auth/login.ts:42`
- **CWE:** CWE-89 (SQL Injection)
- **Entry Point:** POST /api/login (public, no auth)
- **Description:** Unsanitized user input concatenated into SQL query.
- **Evidence:** `const query = "SELECT * FROM users WHERE id = " + req.params.id`
- **Remediation:** Use parameterized queries. Replace string concatenation with prepared statements.

```typescript
// Before (vulnerable)
const query = "SELECT * FROM users WHERE id = " + req.params.id

// After (fixed)
const query = "SELECT * FROM users WHERE id = $1"
const result = await db.query(query, [req.params.id])
```

(Repeat for each critical/high finding)

## Medium & Low Findings

Present as a table for brevity:

| Severity | Finding | Location | Remediation |
|----------|---------|----------|-------------|
| MEDIUM | Outdated dependency X | package.json | Upgrade to vX.Y.Z |
| LOW | Missing CSP header | server.ts:10 | Add Content-Security-Policy header |

## Git Security Signals

Summary of security-relevant git history findings.

## Dependency Status

Table of vulnerable dependencies with CVE IDs and fix versions.

## Recommendations

Prioritized list of remediation actions:
1. **Immediate:** Fix critical findings (list them)
2. **Short-term:** Address high findings, update vulnerable dependencies
3. **Ongoing:** Add security linting to CI, enable Dependabot/Renovate
```

## Error Handling

- If `opensec` is not installed or not in PATH, tell the user to install it: `npm install -g opensec-cli`
- If a scan step fails, log the error, continue with remaining steps, and note incomplete coverage in the report.
- If the target path does not exist or is empty, stop and ask the user for the correct path.
- If no findings are found, still produce a report confirming clean status with the tools/rules that were checked.

## Execution Notes

- Always use `--format json` for programmatic parsing. Never rely on human-readable output.
- Run Steps 2, 3, and 4 in parallel when possible — they are independent.
- Step 5 (correlation) MUST wait for Steps 2 and 3 to complete.
- Step 6 (CVE enrichment) should only run for critical/high dependency findings to avoid rate limits.
- Store all raw JSON outputs in `<OUTPUT_DIR>/raw/` for traceability.
- The final Markdown report should be both displayed in conversation AND saved to `<OUTPUT_DIR>/audit-report.md`.
