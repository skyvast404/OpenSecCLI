---
name: supply-chain-audit
description: >
  Trigger when user asks to "check dependencies", "audit supply chain", "find
  vulnerable packages", "CI/CD security review", "dependency confusion check",
  "SBOM generation", "is this dependency safe", "check npm/pip packages". Use
  for software supply chain security assessments.
---

# Supply Chain Audit Skill

Orchestrate a multi-phase software supply chain security assessment using
OpenSecCLI, covering dependency vulnerabilities, CI/CD pipeline security,
secret detection, and SBOM generation.

## 1. Required Input

- **Project path** (`$PATH`): Absolute path to the repository or project root.

If the user does not provide a path, ask for it before proceeding. Verify the
path exists with a quick `ls` before running any commands.

## 2. Phase 1 — Dependency Audit + Credential Leak Scan (parallel)

Run these two commands in parallel via separate Bash tool calls. Always append
`--format json` for machine-parseable output.

```bash
opensec supply-chain dep-audit --path $PATH --format json
```

```bash
opensec scan analyze --path $PATH --tools gitleaks --format json
```

`dep-audit` scans lock files (package-lock.json, yarn.lock, Pipfile.lock,
go.sum, Cargo.lock, etc.) for known CVEs. `gitleaks` scans the git history
for hardcoded secrets.

## 3. Phase 2 — CI/CD Pipeline Security

```bash
opensec supply-chain ci-audit --path $PATH --format json
```

Analyzes GitHub Actions, GitLab CI, Jenkinsfile, and similar pipeline configs
for insecure patterns: unpinned actions, excessive permissions, secret
exposure in logs, self-hosted runner risks.

## 4. Phase 3 — Secret Detection (deep scan)

```bash
opensec secrets trufflehog-scan --path $PATH --format json
```

TruffleHog performs entropy-based and regex-based secret detection across the
full git history, covering API keys, tokens, private keys, and credentials.

## 5. Phase 4 — SBOM Generation

```bash
opensec supply-chain sbom --path $PATH --format json
```

Generates a Software Bill of Materials (CycloneDX or SPDX format) listing all
direct and transitive dependencies with versions and licenses.

## 6. Phase 5 — Risk Correlation

After collecting Phase 1-4 results, perform targeted lookups:

### CVE Enrichment

For each unique CVE found in `dep-audit` results, query NVD for full details.
Run these in parallel (batch up to 10 at a time):

```bash
opensec nvd cve-get --cve_id $CVE --format json
```

Extract: CVSS score, attack vector, exploit availability, affected versions,
and recommended fix version.

### Dependency Reputation Check

For any dependency flagged as suspicious (typosquat candidate, low download
count, recent ownership transfer), check threat feeds:

```bash
opensec abuse.ch threatfox-search --ioc $PACKAGE --format json
```

This catches packages that have been reported as malware distribution vectors
or dependency confusion targets.

## 7. Error Handling

- If a command fails (non-zero exit, timeout, missing tool), mark that phase
  as `unavailable` in the report. Do NOT stop the audit.
- If ALL commands fail, report that no tools could be reached and suggest the
  user check installation with `opensec --version` and `opensec config show`.
- Parse JSON output safely. If output is not valid JSON, treat that phase as
  errored and include raw stderr in the report.

## 8. Severity Classification

Classify each finding using this matrix:

| Condition | Severity |
|-----------|----------|
| CVE with CVSS >= 9.0, or known exploit in the wild | **Critical** |
| CVE with CVSS 7.0-8.9, or secret exposed in public repo | **High** |
| CVE with CVSS 4.0-6.9, or CI/CD misconfiguration allowing code injection | **Medium** |
| CVE with CVSS < 4.0, informational CI/CD warnings, license compliance | **Low** |

## 9. Output Report Format

Present the final report in this exact markdown structure:

```markdown
# Supply Chain Security Report

**Project:** `<project path>`
**Audited:** <current date/time>
**Ecosystems Detected:** npm | pip | go | cargo | maven | ...

---

## Risk Summary

| Severity | Count |
|----------|-------|
| Critical | X |
| High | X |
| Medium | X |
| Low | X |

---

## Vulnerable Dependencies

| Ecosystem | Package | Installed | Severity | CVE | CVSS | Fix Version |
|-----------|---------|-----------|----------|-----|------|-------------|
| npm | lodash | 4.17.20 | Critical | CVE-2021-23337 | 9.8 | 4.17.21 |
| pip | requests | 2.25.0 | High | CVE-2023-32681 | 7.5 | 2.31.0 |
| ... | ... | ... | ... | ... | ... | ... |

## CI/CD Pipeline Issues

| File | Issue | Severity | Recommendation |
|------|-------|----------|----------------|
| .github/workflows/ci.yml | Unpinned action `actions/checkout@main` | Medium | Pin to SHA hash |
| ... | ... | ... | ... |

## Exposed Secrets

| Source | Type | File/Commit | Status |
|--------|------|-------------|--------|
| gitleaks | AWS Access Key | config.py (line 42) | Active |
| trufflehog | GitHub Token | commit abc123 | Revoked |
| ... | ... | ... | ... |

## SBOM Summary

- **Total dependencies:** X (Y direct, Z transitive)
- **License breakdown:** MIT: X, Apache-2.0: Y, GPL-3.0: Z, Unknown: W
- **Ecosystems:** npm (X pkgs), pip (Y pkgs), ...

## Threat Feed Matches

| Package/IOC | Source | Threat Type | Details |
|-------------|--------|-------------|---------|
| ... | ThreatFox | malware | ... |

---

## Prioritized Fix Plan

### Immediate (Critical + High)
1. Upgrade `lodash` to >= 4.17.21 — CVE-2021-23337 (RCE)
2. Rotate exposed AWS key and revoke old credentials
3. ...

### Short-term (Medium)
1. Pin GitHub Actions to commit SHAs
2. ...

### Long-term (Low)
1. Review GPL-3.0 license compatibility
2. ...

---

## Recommended Actions

1. <Specific action based on findings>
2. <e.g., "Run `npm audit fix` to auto-patch 3 vulnerabilities">
3. <e.g., "Add .gitleaks.toml baseline to suppress known false positives">
4. <e.g., "Enable Dependabot or Renovate for automated dependency updates">
5. <e.g., "Restrict GitHub Actions permissions to read-only by default">
```

## 10. Follow-up Suggestions

After presenting the report, proactively suggest next steps:

- "Want me to check specific CVEs against exploit databases for active exploitation?"
- "Should I generate a detailed SBOM export for compliance submission?"
- "I can audit a specific CI/CD workflow file in more depth if needed."
- "Want me to check if any of these packages have known typosquat variants?"

Offer these only when the results contain leads worth pursuing.
