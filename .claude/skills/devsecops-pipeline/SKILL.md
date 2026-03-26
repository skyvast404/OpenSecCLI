---
name: devsecops-pipeline
description: >
  Trigger when user asks to "set up security in CI/CD", "DevSecOps review",
  "secure the pipeline", "integrate security scanning", "shift-left security",
  "security gates for deployment". Use for integrating security scanning into
  development workflows and CI/CD pipelines.
---

# DevSecOps Pipeline Skill

Orchestrate a comprehensive security assessment of a project's CI/CD pipeline
and codebase, then generate actionable CI/CD security integration configs with
gate thresholds and a remediation roadmap.

## Required Input

- **Project path** (`$PATH`): Absolute path to the repository root.

If the user does not provide a path, ask for it before proceeding. Verify the
path exists with a quick `ls` before running any commands.

## Pre-flight Detection

Before starting, detect what is in scope:

```bash
# Check for CI/CD configs
ls $PATH/.github/workflows/*.yml $PATH/.gitlab-ci.yml $PATH/Jenkinsfile $PATH/.circleci/config.yml 2>/dev/null
```

```bash
# Check for Dockerfiles
find $PATH -maxdepth 3 -name "Dockerfile*" 2>/dev/null | head -10
```

Note which CI platform and containerization is detected.

## Phase 1 -- CI/CD Config + Dependency Audit (parallel)

Run these three commands in parallel via separate Bash tool calls:

```bash
opensec supply-chain ci-audit --path $PATH --format json
```

```bash
opensec supply-chain dep-audit --path $PATH --format json
```

```bash
opensec supply-chain snyk-scan --path $PATH --format json
```

- `ci-audit`: Checks pipeline configs for unpinned actions, excessive
  permissions, secret exposure in logs, self-hosted runner risks.
- `dep-audit`: Scans lock files for known CVEs in dependencies.
- `snyk-scan`: Comprehensive SCA covering transitive dependencies and
  license compliance.

## Phase 2 -- SBOM + Secret Detection (parallel)

```bash
opensec supply-chain sbom --path $PATH --format json
```

```bash
opensec secrets trufflehog-scan --path $PATH --format json
```

- `sbom`: Generates a Software Bill of Materials for compliance.
- `trufflehog-scan`: Entropy and regex-based secret detection across git history.

## Phase 3 -- Static Analysis

```bash
opensec scan analyze --path $PATH --format json
```

SAST scan covering common vulnerability patterns: injection, auth bypass,
insecure crypto, hardcoded credentials, and language-specific issues.

## Phase 4 -- Container Security (conditional)

Run only if Dockerfiles were detected in pre-flight:

```bash
opensec cloud dockerfile-lint --file $DOCKERFILE --format json
```

If multiple Dockerfiles exist, scan each in parallel (limit to 5).
Check for: running as root, unpinned base images, unnecessary packages,
multi-stage build opportunities, secret leakage in layers.

## Error Handling

- If a command fails (non-zero exit, timeout, missing tool), mark that phase
  as `unavailable` in the report. Do NOT stop the assessment.
- If ALL commands fail, report that no tools could be reached and suggest the
  user check installation with `opensec --version` and `opensec config show`.
- Parse JSON output safely. If output is not valid JSON, treat that phase as
  errored and include raw stderr in the report.

## Severity Classification

| Condition | Severity |
|-----------|----------|
| Active secret in repo, RCE-class SAST finding, critical CVE (CVSS >= 9.0) | **Critical** |
| High CVE (CVSS 7.0-8.9), CI/CD allows code injection, unpinned actions with write perms | **High** |
| Medium CVE (CVSS 4.0-6.9), Dockerfile best-practice violations, missing security headers in CI | **Medium** |
| Low CVE (CVSS < 4.0), informational warnings, license compliance notes | **Low** |

## Output Report Format

Present the final report in this exact markdown structure:

```markdown
# DevSecOps Pipeline Security Report

**Project:** `<project path>`
**Assessed:** <current date/time>
**CI Platform:** GitHub Actions | GitLab CI | Jenkins | CircleCI | None detected
**Container:** Dockerfile detected | Not detected

---

## Risk Summary

| Severity | Count |
|----------|-------|
| Critical | X |
| High     | X |
| Medium   | X |
| Low      | X |

---

## CI/CD Pipeline Issues

| File | Issue | Severity | Recommendation |
|------|-------|----------|----------------|
| .github/workflows/ci.yml | Unpinned action | Medium | Pin to SHA |

## Dependency Vulnerabilities

| Package | CVE | CVSS | Severity | Current | Fix Version |
|---------|-----|------|----------|---------|-------------|
| lodash  | CVE-2021-23337 | 9.8 | Critical | 4.17.20 | 4.17.21 |

## SAST Findings

| File | Line | Finding | Severity | CWE |
|------|------|---------|----------|-----|
| src/auth.js | 42 | SQL injection | Critical | CWE-89 |

## Exposed Secrets

| Type | File/Commit | Status |
|------|-------------|--------|
| AWS Access Key | config.py:42 | Active |

## Dockerfile Issues

| File | Issue | Severity |
|------|-------|----------|
| Dockerfile | Running as root | High |

## SBOM Summary

- **Total dependencies:** X (Y direct, Z transitive)
- **License breakdown:** MIT: X, Apache-2.0: Y, Unknown: Z

---

## Recommended CI/CD Security Configuration

### GitHub Actions Example

(Generate a security-scanning workflow YAML snippet with:
- dependency scanning step
- SAST step
- secret detection step
- container scanning step if applicable
- security gate that fails on critical/high findings)

### GitLab CI Example

(Generate equivalent .gitlab-ci.yml snippet if GitLab detected)

---

## Security Gate Thresholds

| Gate | Block on | Warn on |
|------|----------|---------|
| Dependency CVEs | Critical, High | Medium |
| SAST Findings | Critical | High |
| Secret Detection | Any verified secret | Any potential secret |
| Container Scan | Critical, High | Medium |
| License Compliance | GPL in proprietary | Unknown license |

---

## Remediation Roadmap

### Immediate (Day 1)
1. Rotate exposed secrets
2. Fix critical CVEs

### Short-term (Week 1)
1. Pin CI actions to SHA hashes
2. Patch high-severity dependencies
3. Add security scanning to CI pipeline

### Medium-term (Sprint)
1. Address SAST findings
2. Harden Dockerfiles
3. Implement SBOM generation in CI

### Long-term (Quarter)
1. Enable automated dependency updates (Dependabot/Renovate)
2. Add container image signing
3. Implement policy-as-code gates
```

## Follow-up Suggestions

After presenting the report, offer relevant next steps such as generating a
ready-to-commit CI workflow file, investigating specific CVEs, auditing a
particular workflow in depth, or setting up pre-commit hooks for secret detection.
