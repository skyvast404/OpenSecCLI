---
name: quick-security-check
description: >
  Trigger when user gives a URL and asks "is this site secure?", "check security of",
  "security score", "how secure is". Quick 60-second security assessment of any website.
---

# Quick Security Check

Run a fast security assessment against a target URL using only built-in OpenSecCLI commands.

## Workflow

### Step 1: Header Audit

```bash
opensec vuln header-audit --url $URL --format json
```

Parse the JSON output. Extract:
- Overall grade (A-F)
- List of missing security headers
- List of present headers with their values

### Step 2: CORS Check

```bash
opensec vuln cors-check --url $URL --format json
```

Parse the JSON output. Extract:
- Whether CORS is misconfigured
- Specific misconfigurations found (reflected origin, null bypass, wildcard)

### Step 3: Build Scorecard

Combine results into a **Security Scorecard**:

```markdown
# Security Scorecard: <URL>

**Overall Grade:** <A-F from header audit>
**Assessed:** <current date/time>

## Header Findings
| Header | Status | Value |
|--------|--------|-------|
| HSTS | Present/Missing | <value or "—"> |
| CSP | Present/Missing | <value or "—"> |
| X-Frame-Options | Present/Missing | <value or "—"> |
| ... | ... | ... |

## CORS Status
- **Misconfigured:** Yes/No
- **Details:** <findings or "No issues detected">

## Top 3 Recommendations
1. <Most critical fix based on findings>
2. <Second priority>
3. <Third priority>
```

## Error Handling

- If a command fails, note the check as "Unavailable" and continue.
- If both commands fail, suggest running `opensec doctor` to check environment.
