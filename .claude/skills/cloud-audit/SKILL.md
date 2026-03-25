---
name: cloud-audit
description: >
  Trigger when user asks to "audit cloud security", "check AWS/Azure/GCP config",
  "container security review", "Kubernetes security audit", "IaC security scan",
  "cloud posture assessment", "CSPM". Use for cloud infrastructure security
  assessments including IaC scanning, container security, Kubernetes audits, and
  supply chain analysis.
---

# Cloud Security Audit Skill

Orchestrate a comprehensive cloud infrastructure security assessment using
OpenSecCLI, covering IaC misconfigurations, container vulnerabilities, Kubernetes
hardening, supply chain risks, and secrets exposure.

## Required Inputs

- **Project path**: Path to the codebase or IaC repository (required)
- **Container image**: Docker image to scan, e.g. `myapp:latest` (optional)
- **Kubernetes context**: K8s cluster context for live audit (optional)

If only a path is provided, run Phases 1, 4, and 5. Enable Phase 2 only if a
container image is specified or Dockerfiles are detected in the path. Enable
Phase 3 only if a Kubernetes context is specified or K8s manifests are detected.

## Pre-flight Detection

Before starting, check what is in scope:

```bash
# Detect Dockerfiles
find <PATH> -maxdepth 3 -name "Dockerfile*" -o -name "docker-compose*.yml" 2>/dev/null | head -20
```

```bash
# Detect Kubernetes manifests
find <PATH> -maxdepth 3 -name "*.yaml" -o -name "*.yml" 2>/dev/null | xargs grep -l "apiVersion.*kind" 2>/dev/null | head -20
```

Use these results to decide which phases to run. Note detected files in the report.

## Phase 1 — IaC Scanning

Scan infrastructure-as-code for misconfigurations (Terraform, CloudFormation,
Kubernetes manifests, Helm charts, Dockerfiles):

```bash
opensec cloud iac-scan --path <PATH> --format json
```

Parse results for:
- Resource type and file location
- Misconfiguration description and severity
- CIS benchmark or policy rule reference
- Remediation guidance

## Phase 2 — Container Security

Run only if a container image is provided or Dockerfiles are detected.

```bash
opensec cloud container-scan --image <IMAGE> --format json
```

Parse results for:
- OS and library vulnerabilities (CVE, severity, fixed version)
- Dockerfile best-practice violations (running as root, etc.)
- Image layer analysis and bloat

If multiple images are found (e.g., from docker-compose), scan each in parallel
via separate Bash calls. Limit to 5 images max; note any skipped.

## Phase 3 — Kubernetes Audit

Run only if a Kubernetes context is provided or K8s manifests are detected.

```bash
opensec cloud kube-audit --format json
```

Parse results for:
- CIS Kubernetes Benchmark failures
- RBAC misconfigurations
- Pod security violations (privileged containers, host networking, etc.)
- Network policy gaps
- Secrets mounted as environment variables

## Phase 4 — Supply Chain Analysis

Run all three in parallel via separate Bash calls:

```bash
opensec supply-chain dep-audit --path <PATH> --format json
```

```bash
opensec supply-chain ci-audit --path <PATH> --format json
```

```bash
opensec supply-chain sbom --path <PATH> --format json
```

From dep-audit, extract:
- Vulnerable dependencies with CVEs and severity
- Outdated packages with available patches

From ci-audit, extract:
- CI/CD pipeline security issues
- Insecure GitHub Actions, unpinned actions, secret exposure risks

From sbom, extract:
- Full dependency inventory for compliance and audit trail

## Phase 5 — Secrets Detection

Run both in parallel:

```bash
opensec secrets trufflehog-scan --path <PATH> --format json
```

```bash
opensec scan analyze --path <PATH> --format json
```

Parse results for:
- Detected secret types (API keys, tokens, passwords, certificates)
- File path and line number
- Verification status (confirmed active vs. potentially inactive)

## Error Handling

- If a command fails (non-zero exit, timeout, tool not installed), note the source
  as `unavailable` in the report. Do NOT stop the audit.
- If ALL commands fail, report that no tools could be reached and suggest the user
  check installation with `opensec --help` and `opensec config show`.
- Parse JSON output safely. If output is not valid JSON, treat that source as
  errored and include raw stderr in the report.

## Severity Classification

| Severity | Criteria |
|----------|----------|
| **Critical** | Exposed secrets (verified active), RCE-enabling misconfigs, public S3 buckets with sensitive data, privileged container escape paths |
| **High** | Known CVEs in dependencies (CVSS >= 7.0), overly permissive IAM/RBAC, missing encryption at rest, unpinned CI actions with write perms |
| **Medium** | Outdated dependencies with medium CVEs, missing network policies, Dockerfile best-practice violations, TLS misconfigs |
| **Low** | Informational findings, minor best-practice deviations, cosmetic Dockerfile issues |

## Output Report Format

Present the final report in this exact markdown structure:

```markdown
# Cloud Security Posture Report

**Project:** `<PATH>`
**Container Image:** `<IMAGE or N/A>`
**K8s Context:** `<CONTEXT or N/A>`
**Assessed:** <current date/time>

---

## Executive Summary

<2-3 sentences: scope of audit, total findings by severity, overall posture
rating (Critical / Needs Improvement / Acceptable / Strong).>

---

## IaC Misconfigurations

| # | File | Resource | Finding | Severity | Benchmark |
|---|------|----------|---------|----------|-----------|
| 1 | ... | ... | ... | ... | CIS x.y.z |

---

## Container Vulnerabilities

| # | Image | Package | CVE | Severity | Fixed In |
|---|-------|---------|-----|----------|----------|
| 1 | ... | ... | CVE-XXXX-XXXXX | ... | ... |

---

## Kubernetes Audit Findings

| # | Resource | Finding | Severity | CIS Benchmark |
|---|----------|---------|----------|---------------|
| 1 | ... | ... | ... | ... |

---

## Supply Chain Risks

### Vulnerable Dependencies
| # | Package | CVE | Severity | Current | Patched |
|---|---------|-----|----------|---------|---------|
| 1 | ... | ... | ... | ... | ... |

### CI/CD Pipeline Issues
| # | Finding | Severity | File | Details |
|---|---------|----------|------|---------|
| 1 | ... | ... | ... | ... |

---

## Exposed Secrets

| # | Type | File | Line | Status |
|---|------|------|------|--------|
| 1 | AWS Key | ... | ... | Verified Active / Potentially Active |

**IMMEDIATE ACTION**: Rotate any verified-active secrets before proceeding
with other remediation.

---

## Prioritized Remediation Plan

### P0 — Immediate (Critical)
1. <Rotate exposed secrets>
2. <Fix RCE-enabling misconfigs>

### P1 — This Sprint (High)
1. <Patch high-CVE dependencies>
2. <Fix IAM/RBAC over-permissions>

### P2 — Next Sprint (Medium)
1. <Address container best practices>
2. <Add network policies>

### P3 — Backlog (Low)
1. <Minor hardening improvements>
```

## Follow-up Suggestions

After presenting the report, proactively suggest next steps:

- "Want me to scan additional container images found in the compose file?"
- "Should I investigate any of the CVEs for exploit availability?"
- "I can generate a detailed SBOM export for compliance reporting."
- "Want me to re-scan after you apply the recommended fixes?"

Offer these only when the results contain leads worth pursuing.
