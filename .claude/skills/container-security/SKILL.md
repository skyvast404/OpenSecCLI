---
name: container-security
description: >
  Trigger when user asks to "check container security", "scan Docker image",
  "Kubernetes security review", "is this container safe", "Docker security
  audit", "container hardening", "scan my Dockerfile", "K8s security check",
  "CIS Docker benchmark", "container vulnerability scan". Use for comprehensive
  container and orchestration security assessment.
---

# Container & Orchestration Security Assessment

Perform a comprehensive container security assessment using OpenSecCLI adapters,
covering Dockerfile best practices, image vulnerability scanning, CIS compliance,
and Kubernetes cluster hardening.

## Required Inputs

| Parameter | Required | Description |
|-----------|----------|-------------|
| `IMAGE`   | No*      | Docker image to scan (e.g., `myapp:latest`) |
| `FILE`    | No*      | Path to Dockerfile |
| `PATH`    | No*      | Path to project (auto-detect Dockerfiles and K8s manifests) |

*At least one of `IMAGE`, `FILE`, or `PATH` must be provided. If only `PATH`
is given, auto-detect Dockerfiles and Kubernetes manifests within it.

## Pre-flight Detection

If `PATH` is provided, detect available artifacts:

```bash
find <PATH> -maxdepth 3 -name "Dockerfile*" -o -name "docker-compose*.yml" 2>/dev/null | head -20
```

```bash
find <PATH> -maxdepth 3 \( -name "*.yaml" -o -name "*.yml" \) 2>/dev/null | xargs grep -l "apiVersion" 2>/dev/null | head -20
```

```bash
kubectl config current-context 2>/dev/null
```

Use detection results to determine which phases to run:
- Dockerfiles found or `FILE` provided --> Phase 1 (Dockerfile Lint)
- `IMAGE` provided --> Phase 2 (Image Scan) + Phase 3 (CIS Lint)
- K8s manifests found or `kubectl` context available --> Phase 4 + Phase 5

---

## Phase 1 --- Dockerfile Lint (hadolint)

Run for each detected Dockerfile (max 5):

```bash
opensec cloud dockerfile-lint --file <DOCKERFILE_PATH> --format json
```

From results, extract:
- Rule code (e.g., DL3006, DL3008, SC2086)
- Severity (error, warning, info, style)
- Line number and instruction
- Description and remediation
- Group by category: security, maintainability, efficiency

Key security rules to highlight:
- **DL3002**: Last user should not be root
- **DL3004**: Do not use sudo
- **DL3006**: Always tag the base image version
- **DL3008**: Pin versions in apt-get install
- **DL3009**: Delete apt-get lists after install
- **DL3018**: Pin versions in apk add
- **DL3020**: Use COPY instead of ADD for files
- **DL3022**: Use COPY --from for multi-stage builds

## Phase 2 --- Image Vulnerability Scan (trivy)

```bash
opensec cloud container-scan --image $IMAGE --format json
```

From results, extract:
- OS and library vulnerabilities grouped by severity
- CVE ID, package name, installed version, fixed version
- CVSS score and exploitability metrics where available
- Total vulnerability counts by severity

## Phase 3 --- CIS Compliance Lint (dockle)

```bash
opensec cloud container-lint --image $IMAGE --format json
```

From results, extract:
- CIS Docker Benchmark check results
- FATAL, WARN, INFO, SKIP, PASS categories
- Specific findings: setuid/setgid files, credential files, unnecessary
  packages, missing HEALTHCHECK, running as root

## Phase 4 --- Kubernetes Security Scan (kubescape)

Run only if K8s manifests or cluster access is detected:

```bash
opensec cloud kube-security --framework nsa --format json
```

From results, extract:
- Framework compliance score (NSA/CISA hardening)
- Failed controls grouped by severity
- Affected resources (namespace, kind, name)
- Remediation guidance per control
- MITRE ATT&CK mapping where available

## Phase 5 --- CIS Kubernetes Benchmark (kube-bench)

Run only if a live K8s cluster is accessible:

```bash
opensec cloud kube-audit --format json
```

From results, extract:
- CIS Kubernetes Benchmark section results
- PASS, FAIL, WARN, INFO counts per section
- Failed checks with description and remediation
- Sections: Control Plane, etcd, API Server, Scheduler, Controller Manager,
  Worker Nodes, Policies

---

## Error Handling

- If a command fails (non-zero exit, tool not installed, image not found),
  log the error, mark that phase as `Skipped`, and continue.
- If ALL commands fail, suggest verifying installation: `opensec --help`.
- If image pull fails, suggest `docker pull <IMAGE>` first.
- Parse JSON output safely. Non-JSON output is treated as errored.

---

## Output --- Container Security Report

### 1. Executive Summary

```
Assessment Date:   <current date>
Dockerfile(s):     <paths or N/A>
Container Image:   <IMAGE or N/A>
K8s Context:       <context or N/A>
Phases Completed:  <list>
Phases Skipped:    <list with reasons>

Total Findings:    <N>
  Critical: <n>    High: <n>    Medium: <n>    Low: <n>    Info: <n>

Overall Posture:   Critical / Needs Improvement / Acceptable / Strong
```

### 2. Dockerfile Analysis

| # | File | Line | Rule | Severity | Finding | Fix |
|---|------|------|------|----------|---------|-----|
| 1 | ... | ... | DLxxxx | ... | ... | ... |

### 3. Image Vulnerabilities

| # | Package | CVE | Severity | CVSS | Installed | Fixed In |
|---|---------|-----|----------|------|-----------|----------|
| 1 | ... | CVE-XXXX-XXXXX | ... | ... | ... | ... |

### 4. CIS Docker Compliance

| # | Check | Status | Finding | Remediation |
|---|-------|--------|---------|-------------|
| 1 | ... | FATAL/WARN | ... | ... |

### 5. Kubernetes Security

| # | Control | Framework | Severity | Resources Affected | Remediation |
|---|---------|-----------|----------|-------------------|-------------|
| 1 | ... | NSA/CIS | ... | ... | ... |

### 6. Prioritized Remediation Plan

#### P0 --- Immediate (Critical)
1. Fix critical CVEs with known exploits
2. Remove running as root from Dockerfiles
3. Rotate any credentials found in image layers

#### P1 --- This Sprint (High)
1. Pin base image versions and dependency versions
2. Fix CIS benchmark FATAL findings
3. Add network policies for K8s namespaces

#### P2 --- Next Sprint (Medium)
1. Multi-stage builds to reduce attack surface
2. Add HEALTHCHECK instructions
3. Remove unnecessary packages and setuid binaries

#### P3 --- Backlog (Low)
1. Dockerfile style and maintainability improvements
2. Image size optimization

---

## Follow-up Suggestions

After presenting the report, offer relevant next steps:

- "Want me to scan additional images from your docker-compose file?"
- "Should I investigate any of the critical CVEs for exploit availability?"
- "I can generate a hardened Dockerfile based on the findings."
- "Want me to re-scan after you apply the fixes?"
