---
name: compliance-check
description: >
  Trigger when user asks to "check compliance", "CIS benchmark", "PCI DSS audit",
  "OWASP compliance", "SOC 2 readiness", "security baseline assessment",
  "hardening check". Use for assessing infrastructure and application compliance
  against security frameworks.
---

# Compliance Check Skill

Assess infrastructure and application security posture against industry frameworks
(OWASP Top 10, CIS Benchmarks, PCI DSS) using OpenSecCLI. Produce a structured
compliance report with pass/fail per control, gap analysis, and remediation priority.

## Required Input

- **Target URL** (`$URL` / `$HOST`): Web application URL for OWASP checks.
- **Project path** (`$PATH`): Path to codebase for SAST and dependency checks.
- **Cloud provider** (`$PROVIDER`): aws, azure, or gcp (optional, for cloud posture).
- **Container image** (`$IMAGE`): Docker image name (optional, for container checks).
- **Framework focus** (optional): Which frameworks to assess against. Defaults to
  all applicable frameworks.

At minimum, one of `$URL` or `$PATH` must be provided. Ask the user for missing
inputs before proceeding.

## Pre-flight Detection

Determine which assessment modules to enable:

```bash
# Check for Dockerfiles
find $PATH -maxdepth 3 -name "Dockerfile*" 2>/dev/null | head -10
```

```bash
# Check for Kubernetes manifests
find $PATH -maxdepth 3 \( -name "*.yaml" -o -name "*.yml" \) 2>/dev/null | xargs grep -l "apiVersion" 2>/dev/null | head -10
```

```bash
# Check for cloud provider configs
ls $PATH/terraform/ $PATH/cloudformation/ $PATH/pulumi/ $PATH/.aws/ 2>/dev/null
```

Use detection results to decide which modules to activate.

## Module 1 -- Web Application (OWASP Top 10)

Run if `$URL` is provided. Execute in parallel:

```bash
opensec vuln header-audit --url $URL --format json
```

```bash
opensec vuln tls-check --host $HOST --format json
```

```bash
opensec vuln cors-check --url $URL --format json
```

Map results to OWASP Top 10 2021: A01 (CORS/access control), A02 (TLS/HSTS),
A05 (missing headers/misconfig), A07 (auth/cookie flags). Categories A03, A06,
A08, A10 are covered by SAST/dep-audit in Module 3. A04 and A09 require manual
review.

## Module 2 -- Infrastructure (CIS Benchmarks)

Run applicable checks based on pre-flight detection.

### Kubernetes (if K8s manifests or cluster detected)

```bash
opensec cloud kube-security --framework cis-v1.23 --format json
```

Maps to CIS Kubernetes Benchmark v1.23 controls: API server config, etcd
security, controller manager, scheduler, worker nodes, policies.

### Cloud Posture (if cloud provider specified)

```bash
opensec cloud cloud-posture --provider $PROVIDER --format json
```

Maps to CIS AWS/Azure/GCP Foundations Benchmark: IAM, logging, monitoring,
networking, storage encryption, key management.

### Docker (if Dockerfiles detected)

```bash
opensec cloud dockerfile-lint --file $DOCKERFILE --format json
```

Maps to CIS Docker Benchmark: host config, daemon config, container images,
container runtime, security operations.

### Container Image (if image specified)

```bash
opensec cloud container-lint --image $IMAGE --format json
```

Checks for: OS vulnerabilities, outdated packages, unnecessary setuid binaries,
root user, secrets in image layers.

Run all applicable Module 2 checks in parallel.

## Module 3 -- Code Security (OWASP SAST + Supply Chain)

Run if `$PATH` is provided. Execute all three in parallel:

```bash
opensec scan analyze --path $PATH --format json
```

```bash
opensec supply-chain dep-audit --path $PATH --format json
```

```bash
opensec secrets trufflehog-scan --path $PATH --format json
```

- `scan analyze`: SAST for injection, auth bypass, insecure crypto, XSS sinks.
- `dep-audit`: Known CVEs in dependencies (maps to OWASP A06).
- `trufflehog-scan`: Secrets in code/history (maps to PCI DSS Req 6.5).

## Error Handling

- If a command fails, mark that control as `Not Assessed` with reason.
  Do NOT stop the audit.
- If ALL commands fail, suggest checking `opensec --version`.
- Clearly distinguish between `Pass`, `Fail`, `Not Assessed`, and
  `Not Applicable` in the report.

## Framework Mapping

After collecting results, map findings to frameworks. For OWASP, identify the
category and pass/fail status. For CIS, reference specific control IDs (e.g.,
CIS Docker 4.1, CIS K8s 1.2.3). For PCI DSS (if requested), map to: Req 2.2
(hardening via CIS), 6.2 (patching via dep-audit), 6.5 (secure coding via
SAST/secrets), 6.6 (web protection via headers/TLS), 8.2 (auth via TLS),
10.2 (logging, manual), 11.2 (vuln scanning via all modules).

## Output -- Compliance Assessment Report

```markdown
# Compliance Assessment Report

**Target:** `$URL` / `$PATH`
**Assessed:** <current date/time>
**Frameworks:** OWASP Top 10 | CIS Docker | CIS Kubernetes | PCI DSS

---

## Executive Summary

<2-3 sentences: overall compliance posture, critical gaps, and readiness level.>

**Overall Score:** X/Y controls passing (Z%)

---

## OWASP Top 10 Compliance

| OWASP ID | Category | Status | Findings | Severity |
|----------|----------|--------|----------|----------|
| A01 | Broken Access Control | FAIL | CORS allows * with credentials | High |
| A02 | Cryptographic Failures | PASS | TLS 1.3, strong ciphers | - |
| A03 | Injection | FAIL | 2 SQLi patterns in SAST | Critical |
| A05 | Security Misconfiguration | FAIL | Missing CSP, X-Frame-Options | Medium |
| A06 | Vulnerable Components | FAIL | 3 critical CVEs | Critical |

---

## CIS Benchmark Compliance

### Docker (CIS Docker Benchmark v1.6)

| Control ID | Description | Status | Finding |
|------------|-------------|--------|---------|
| 4.1 | Create user for container | FAIL | Running as root |
| 4.6 | Add HEALTHCHECK | FAIL | No HEALTHCHECK |
| 4.7 | Do not use update in Dockerfile | PASS | - |

### Kubernetes (CIS Kubernetes Benchmark v1.23)

| Control ID | Description | Status | Finding |
|------------|-------------|--------|---------|
| 1.2.1 | API server anonymous auth | FAIL | anonymous-auth=true |
| 5.2.1 | Pod Security Standards | PASS | Restricted profile |

---

## PCI DSS Controls (if applicable)

| Requirement | Description | Status | Evidence |
|-------------|-------------|--------|----------|
| 2.2 | System hardening | PARTIAL | Docker: 3 fails, K8s: 2 fails |
| 6.2 | Patch management | FAIL | 5 unpatched CVEs |
| 6.5 | Secure development | FAIL | 2 injection findings |

---

## Gap Analysis & Remediation Priority

Organize gaps by severity (Critical/High/Medium) with framework control references.
Then provide a prioritized remediation plan:
- **P0 (Compliance Blockers):** Injection fixes, critical CVE patches, root containers
- **P1 (High Priority):** CORS restrictions, CSP headers, K8s audit logging
- **P2 (Medium):** Dockerfile best practices, rate limiting
- **P3 (Hardening):** Certificate transparency, license compliance
```

## Follow-up Suggestions

After presenting the report, offer relevant next steps such as deep-diving into
a specific framework, re-assessing after remediation, generating a compliance
evidence package for auditors, or checking specific CIS controls in detail.
