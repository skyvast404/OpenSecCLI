# Contributing to OpenSecCLI

## Quick Start: Add a YAML Adapter (15 minutes)

### 1. Scaffold

```bash
opensec create adapter myapi/lookup --type yaml --strategy api_key --domain threat-intel
```

This generates `myapi/lookup.yaml` with a template to fill in.

### 2. Edit

Fill in the `TODO` sections: API URL, request format, response mapping.

### 3. Test locally

Drop the file into `~/.openseccli/plugins/my-adapter/adapters/myapi/lookup.yaml` and run:

```bash
opensec list --domain threat-intel  # verify it appears
opensec myapi lookup --target test  # verify it works
```

### 4. Submit

- **Community adapters**: Open a PR to this repo under `src/adapters/`
- **Plugin package**: Publish as `opensec-adapter-<name>` on npm

---

## Security Domains

Every adapter must specify a `domain` field:

| Domain | Description | Examples |
|--------|-------------|----------|
| `threat-intel` | Threat intelligence feeds and reputation lookups | VirusTotal, AbuseIPDB, Shodan |
| `code-security` | Static analysis, SAST, code review | Semgrep, Gitleaks |
| `recon` | Reconnaissance, asset discovery, OSINT | subfinder, nmap, httpx |
| `vuln-scan` | Vulnerability scanning, misconfig detection | nuclei, nikto, testssl.sh |
| `secrets` | Secret and credential detection | TruffleHog |
| `supply-chain` | Dependency audit, CI/CD security, SBOM | npm audit, checkov, syft |
| `cloud-security` | Cloud posture, IaC, containers, Kubernetes | checkov, trivy, kube-bench |
| `forensics` | File analysis, binary RE, PCAP, mobile | binwalk, checksec, tshark |
| `pentest` | Active testing utilities | HTTP request crafting, race testing |

---

## YAML Adapter Schema

```yaml
provider: myapi           # Provider group name
name: lookup              # Command name (opensec myapi lookup)
description: "..."        # One-line description
strategy: API_KEY         # FREE or API_KEY
domain: threat-intel      # Security domain (see table above)
auth: myapi               # Auth provider name (for API_KEY strategy)

args:
  target:
    type: string          # string, number, or boolean
    required: true
    help: "Target to look up"

pipeline:
  - request:
      url: "https://api.example.com/v1/{{ args.target }}"
      headers:
        Authorization: "Bearer {{ auth.api_key }}"

  - select:
      path: data          # Extract nested array (optional)

  - map:
      template:
        id: "{{ item.id }}"
        result: "{{ item.result }}"

columns: [id, result]
```

---

## TypeScript Adapter Guide

Use TypeScript when you need to:
- Wrap external CLI tools (nmap, nuclei, etc.)
- Run multiple tools in parallel
- Apply complex parsing logic
- Implement pure-TypeScript functionality (no external deps)

```bash
opensec create adapter my-scanner/scan --type typescript --domain vuln-scan
```

---

## Code Standards

- **Immutability**: Create new objects, never mutate
- **Functions**: < 50 lines
- **Files**: < 800 lines
- **Errors**: Use `ToolNotFoundError` for missing tools, `CliError` hierarchy for others
- **Security**: Always use `execFile` (never `exec`), validate all user input
- **Testing**: Every adapter needs at least a pipeline/registration test

---

## Testing

```bash
npm test              # Unit tests
npm run test:adapter  # Adapter pipeline tests (mocked HTTP)
npm run test:all      # Everything
```

### Writing adapter tests

Mock `fetch` and test the full pipeline:

```typescript
import { executePipeline } from '../../src/pipeline/executor.js'

vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
  ok: true,
  headers: new Headers({ 'content-type': 'application/json' }),
  json: () => Promise.resolve(mockResponse),
}))

const result = await executePipeline(def.pipeline, {
  args: { target: 'test' },
  auth: { api_key: 'test-key' },
})
```
