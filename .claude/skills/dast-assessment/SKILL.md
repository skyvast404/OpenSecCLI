---
name: dast-assessment
description: >
  Trigger when user asks to "run DAST scan", "dynamic security test",
  "runtime web scan", "ZAP scan this site", "find runtime vulnerabilities",
  "dynamic application security testing", "scan running application",
  "test live site for vulns". Use for dynamic application security testing
  combining automated scanners with manual verification.
---

# Dynamic Application Security Testing (DAST) Assessment

Orchestrate a multi-scanner dynamic security assessment against a live web
application using OpenSecCLI adapters. Combines ZAP baseline scanning, XSS
detection, template-based vulnerability scanning, and header/protocol checks
into a unified, deduplicated report.

> **AUTHORIZATION WARNING**: Before proceeding, confirm with the user that they
> have explicit written authorization to test the target. Dynamic security
> testing sends live payloads to the application and may trigger alerts, cause
> instability, or violate terms of service. If the user cannot confirm
> authorization, do NOT proceed. State the legal requirement and stop.

## Required Input

| Parameter | Required | Description |
|-----------|----------|-------------|
| `URL`     | Yes      | Full target URL (e.g., `https://app.example.com`) |

Extract `DOMAIN` from the URL by stripping the scheme, port, and path.
If the user provides only a domain, prepend `https://` as the default URL.

---

## Workflow

### Phase 1 --- Baseline Scan

Run the ZAP baseline scan to establish an initial vulnerability profile:

```bash
opensec dast zap-scan --url $URL --scan_type baseline --format json
```

From the results, extract:
- Alert name, risk level, confidence, URL, description, and solution
- CWE and WASC IDs for each alert
- Total alert count by risk level (High, Medium, Low, Informational)

### Phase 2 --- Targeted Vulnerability Scanning (run in parallel)

Launch all five commands simultaneously:

```bash
opensec vuln xss-scan --url $URL --format json
```

```bash
opensec vuln nuclei-scan --target $URL --format json
```

```bash
opensec vuln crlf-scan --url $URL --format json
```

```bash
opensec vuln header-audit --url $URL --format json
```

```bash
opensec vuln cors-check --url $URL --format json
```

From the results, extract:
- **XSS (dalfox)**: Vulnerable parameter, payload, injection point, PoC URL
- **Nuclei**: Template ID, matched URL, severity, description, reference
- **CRLF injection**: Vulnerable URL, injected header, response evidence
- **Security headers**: Missing or misconfigured headers with risk rating
- **CORS**: Origin reflection behavior, credentials policy, exploitability

### Phase 3 --- Correlation & Deduplication

After all scans complete:

1. **Deduplicate**: Merge findings that reference the same URL + vulnerability
   type. Prefer the source with the richer evidence (e.g., dalfox XSS detail
   over a ZAP XSS alert for the same parameter).
2. **Correlate**: Link related findings (e.g., missing CSP header + confirmed
   XSS = higher exploitability; CORS misconfiguration + XSS = credential theft
   chain).
3. **Validate**: Flag findings where multiple scanners agree as "Confirmed".
   Single-scanner findings are "Probable". ZAP informational-only alerts with
   no corroboration are "Informational".

---

## Error Handling

- If any `opensec` command fails (non-zero exit, timeout, missing tool),
  log the error, mark that check as `Skipped` in the report, and continue.
- If ALL commands fail, report the failure and suggest the user verify
  installation with `opensec config show`.
- Never let a single failed step abort the entire assessment.
- Parse JSON output safely. If output is not valid JSON, treat that source
  as errored and include raw stderr in a **Data Gaps** section.

---

## Output --- DAST Assessment Report

Present findings in this structure:

### 1. Executive Summary

```
Target:           $URL
Domain:           $DOMAIN
Date:             <current date>
Scan Type:        Dynamic (DAST)
Authorization:    Confirmed by user

Total findings:   <N> (deduplicated)
  Critical: <n>
  High:     <n>
  Medium:   <n>
  Low:      <n>
  Info:     <n>

Scanners used:    ZAP, dalfox, Nuclei, CRLFuzz, Header Audit, CORS Check
Scanners skipped: <list or "None">
```

One-paragraph summary of the overall security posture and most significant
runtime risks discovered.

### 2. Confirmed Findings (Multi-Scanner)

Findings validated by two or more scanners. For each:

| Field | Value |
|-------|-------|
| **Title** | Descriptive name |
| **Severity** | Critical / High / Medium / Low |
| **CWE** | CWE ID if available |
| **Location** | URL, parameter, or endpoint |
| **Scanners** | Which tools detected this |
| **Evidence** | Response snippet, payload, or PoC |
| **Impact** | What an attacker could achieve |
| **Remediation** | Specific fix with code or config example |

### 3. Probable Findings (Single Scanner)

Findings from only one scanner. Same table format as above, plus a
**Confidence** note explaining why manual verification is recommended.

### 4. Attack Chain Analysis

Identify exploitable chains by connecting related findings:

| Chain | Findings | Impact | Likelihood |
|-------|----------|--------|------------|
| XSS + Missing CSP | #1, #5 | Session hijack via inline script | High |
| CORS + XSS | #2, #1 | Cross-origin credential theft | High |
| CRLF + Open Redirect | #3, #7 | Cache poisoning, phishing | Medium |

Only include chains where findings logically compose into a higher-impact
attack. If no chains exist, omit this section.

### 5. Security Header Scorecard

| Header | Status | Value / Issue |
|--------|--------|---------------|
| Content-Security-Policy | Missing / Present | details |
| Strict-Transport-Security | Missing / Present | details |
| X-Frame-Options | Missing / Present | details |
| X-Content-Type-Options | Missing / Present | details |
| Referrer-Policy | Missing / Present | details |
| Permissions-Policy | Missing / Present | details |
| CORS Policy | Safe / Misconfigured | details |

### 6. Remediation Roadmap

Order by severity and effort:

| Priority | Finding | Effort | Recommendation |
|----------|---------|--------|----------------|
| 1 | Reflected XSS in /search | Medium | Input validation + CSP |
| 2 | Missing HSTS | Low | Add Strict-Transport-Security header |
| 3 | CORS allows arbitrary origins | Low | Restrict allowed origins |

### 7. Data Gaps

List any checks that were skipped or errored, with the reason and how to
enable them.

---

## Follow-up Suggestions

After presenting the report, offer relevant next steps:

- "Want me to run an authenticated ZAP scan for deeper coverage?"
- "I can test specific parameters for SQL injection or SSTI."
- "Should I run a full active scan instead of the baseline?"
- "I can perform source code analysis to trace the root cause of any finding."
