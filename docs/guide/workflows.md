# Declarative Workflows

Define multi-step security pipelines in YAML. Run them with one command.

## Running a workflow

```bash
opensec workflow run workflows/web-audit.yaml --target example.com
```

Output:

```
[1/4] Header Audit (1.1s) — 11 findings
[2/4] CORS Check (3.3s) — 10 findings
[3/4] Certificate Check (0.5s) — 20 findings
[4/4] Tech Fingerprint (2.5s) — 1 finding
```

## Workflow format

```yaml
name: my-workflow
description: What this workflow does
variables:
  domain: "{{ target }}"
  url: "https://{{ target }}"
steps:
  - name: Step Name
    command: domain/command-name
    args: { key: "{{ variable }}" }
  - name: Optional Step
    command: domain/command-name
    args: { key: "{{ variable }}" }
    on_error: skip    # continue if this step fails
```

### Fields

| Field | Required | Description |
|-------|----------|-------------|
| `name` | yes | Workflow name |
| `description` | no | Human-readable description |
| `variables` | no | Computed variables from `{{ target }}` |
| `steps[].name` | yes | Step display name |
| `steps[].command` | yes | OpenSecCLI command as `domain/command` |
| `steps[].args` | yes | Arguments passed to the command |
| `steps[].on_error` | no | `skip` to continue on failure (default: abort) |

## Built-in workflows

### web-audit.yaml

Quick web security audit. Runs header audit, CORS check, cert transparency search, and tech fingerprint.

```yaml
name: web-audit
description: Quick web security audit
variables:
  domain: "{{ target }}"
  url: "https://{{ target }}"
steps:
  - name: Header Audit
    command: vuln/header-audit
    args: { url: "{{ url }}" }
  - name: CORS Check
    command: vuln/cors-check
    args: { url: "{{ url }}" }
  - name: Certificate Check
    command: crtsh/cert-search
    args: { domain: "{{ domain }}" }
  - name: Tech Fingerprint
    command: recon/tech-fingerprint
    args: { target: "{{ url }}" }
    on_error: skip
```

### code-audit.yaml

Source code security audit. Runs SAST, dependency audit, CI/CD audit, secret scan, and project discovery.

```yaml
name: code-audit
description: Source code security audit
variables:
  project: "{{ target }}"
steps:
  - name: SAST Scan
    command: scan/analyze
    args: { path: "{{ project }}" }
  - name: Dependency Audit
    command: supply-chain/dep-audit
    args: { path: "{{ project }}" }
  - name: CI/CD Audit
    command: supply-chain/ci-audit
    args: { path: "{{ project }}" }
  - name: Secret Scan
    command: secrets/trufflehog-scan
    args: { path: "{{ project }}" }
    on_error: skip
  - name: Project Discovery
    command: scan/discover
    args: { path: "{{ project }}" }
```

## Writing custom workflows

1. Create a YAML file in `workflows/` (or anywhere)
2. Use `{{ target }}` as the input variable passed via `--target`
3. Define computed variables from `{{ target }}`
4. List steps in execution order
5. Use `on_error: skip` for non-critical steps

```bash
opensec workflow run ./my-custom-workflow.yaml --target myapp.com
```
