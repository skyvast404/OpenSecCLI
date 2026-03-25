# Phase 2: Ecosystem — External Tools, Plugins, Enrichment, CI

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Complete the enrichment suite (domain + hash), add external tool integration (nmap/nuclei subprocess step), shell completion, CI pipeline, and GitHub issue templates to attract contributors.

**Architecture:** `subprocess` pipeline step wraps local tools via `execFile` (never string concat). Domain/hash enrichment adapters follow the same TS pattern as ip-enrich. Shell completion uses Commander.js built-in. CI via GitHub Actions: test + lint + security audit.

**Tech Stack:** TypeScript, YAML, GitHub Actions, Commander.js completion

---

## Pre-requisites

- Phase 0+1 complete: 16 adapters, 18 tests all pass
- `npm install` done, `npx tsx src/main.ts list` shows 16 adapters

---

### Task 1: Domain Enrichment Adapter

**Files:**
- Create: `src/adapters/_enrichment/domain-enrich.ts`
- Test: `tests/adapter/domain-enrichment.test.ts`

**Step 1: Write the failing test**

```typescript
// tests/adapter/domain-enrichment.test.ts
import { describe, it, expect, vi, beforeEach } from 'vitest'

describe('enrichment/domain-enrich', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true,
      headers: new Headers({ 'content-type': 'application/json' }),
      json: () => Promise.resolve({}),
    }))
  })

  it('is registered after import', async () => {
    await import('../../src/adapters/_enrichment/domain-enrich.js')
    const { getRegistry } = await import('../../src/registry.js')
    const cmd = getRegistry().get('enrichment/domain-enrich')
    expect(cmd).toBeDefined()
    expect(cmd!.provider).toBe('enrichment')
    expect(cmd!.name).toBe('domain-enrich')
    expect(cmd!.args).toHaveProperty('domain')
  })
})
```

**Step 2: Run test to verify it fails**

Run: `npx vitest run tests/adapter/domain-enrichment.test.ts`
Expected: FAIL — module not found

**Step 3: Write the adapter**

```typescript
// src/adapters/_enrichment/domain-enrich.ts
import { cli, Strategy } from '../../registry.js'
import type { ExecContext } from '../../types.js'
import { loadAuth } from '../../auth/index.js'

interface SourceConfig {
  name: string
  provider: string
  url: (domain: string) => string
  method?: string
  headers: (key: string) => Record<string, string>
  body?: (domain: string) => unknown
  select?: string
  fields: Record<string, string>
}

const SOURCES: SourceConfig[] = [
  {
    name: 'VirusTotal',
    provider: 'virustotal',
    url: (d) => `https://www.virustotal.com/api/v3/domains/${d}`,
    headers: (key) => ({ 'x-apikey': key, Accept: 'application/json' }),
    fields: {
      malicious: 'data.attributes.last_analysis_stats.malicious',
      reputation: 'data.attributes.reputation',
      registrar: 'data.attributes.registrar',
    },
  },
  {
    name: 'crt.sh',
    provider: 'crtsh',
    url: (d) => `https://crt.sh/?q=${encodeURIComponent(d)}&output=json`,
    headers: () => ({ Accept: 'application/json' }),
    fields: { cert_count: '__length__' },
  },
  {
    name: 'Shodan',
    provider: 'shodan',
    url: (d) => `https://api.shodan.io/dns/resolve?hostnames=${d}`,
    headers: () => ({ Accept: 'application/json' }),
    fields: { resolved_ip: '__first_value__' },
  },
]

cli({
  provider: 'enrichment',
  name: 'domain-enrich',
  description: 'Enrich domain from multiple sources in parallel',
  strategy: Strategy.FREE,
  args: {
    domain: { type: 'string', required: true, help: 'Domain to enrich' },
  },
  columns: ['source', 'status', 'detail'],

  async func(ctx: ExecContext, args: Record<string, unknown>): Promise<unknown> {
    const domain = args.domain as string
    const timeout = 15_000

    const activeSources = SOURCES.filter(s => {
      if (s.provider === 'crtsh') return true
      const creds = loadAuth(s.provider)
      return creds?.api_key != null
    })

    const results = await Promise.allSettled(
      activeSources.map(async (source) => {
        const creds = loadAuth(source.provider)
        const apiKey = creds?.api_key ?? ''

        let url = source.url(domain)
        if (source.provider === 'shodan' && apiKey) {
          url += `&key=${apiKey}`
        }

        const fetchOpts: RequestInit = {
          method: source.method ?? 'GET',
          headers: source.headers(apiKey),
          signal: AbortSignal.timeout(timeout),
        }

        if (source.body) {
          fetchOpts.body = JSON.stringify(source.body(domain))
        }

        const response = await fetch(url, fetchOpts)
        if (!response.ok) {
          return { source: source.name, status: 'error', detail: `HTTP ${response.status}` }
        }

        const data = await response.json()
        const detail: string[] = []

        for (const [label, path] of Object.entries(source.fields)) {
          if (path === '__length__') {
            detail.push(`${label}: ${Array.isArray(data) ? data.length : 0}`)
          } else if (path === '__first_value__') {
            const vals = data && typeof data === 'object' ? Object.values(data) : []
            detail.push(`${label}: ${vals[0] ?? 'N/A'}`)
          } else {
            const val = walkPath(data, path.split('.'))
            if (val !== undefined && val !== null) {
              detail.push(`${label}: ${val}`)
            }
          }
        }

        return { source: source.name, status: 'ok', detail: detail.join(', ') || '-' }
      }),
    )

    return results.map((r, i) => {
      if (r.status === 'fulfilled') return r.value
      return { source: activeSources[i].name, status: 'error', detail: (r.reason as Error).message }
    })
  },
})

function walkPath(value: unknown, segments: string[]): unknown {
  for (const segment of segments) {
    if (value === null || value === undefined) return undefined
    if (Array.isArray(value) && /^\d+$/.test(segment)) {
      value = value[parseInt(segment, 10)]
    } else if (typeof value === 'object') {
      value = (value as Record<string, unknown>)[segment]
    } else {
      return undefined
    }
  }
  return value
}
```

**Step 4: Run test**

Run: `npx vitest run tests/adapter/domain-enrichment.test.ts`
Expected: PASS

**Step 5: Commit**

```bash
git add src/adapters/_enrichment/domain-enrich.ts tests/adapter/domain-enrichment.test.ts
git commit -m "feat: add domain-enrich multi-source enrichment adapter"
```

---

### Task 2: Hash Enrichment Adapter

**Files:**
- Create: `src/adapters/_enrichment/hash-enrich.ts`
- Test: `tests/adapter/hash-enrichment.test.ts`

**Step 1: Write the failing test**

```typescript
// tests/adapter/hash-enrichment.test.ts
import { describe, it, expect, vi, beforeEach } from 'vitest'

describe('enrichment/hash-enrich', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true,
      headers: new Headers({ 'content-type': 'application/json' }),
      json: () => Promise.resolve({}),
    }))
  })

  it('is registered after import', async () => {
    await import('../../src/adapters/_enrichment/hash-enrich.js')
    const { getRegistry } = await import('../../src/registry.js')
    const cmd = getRegistry().get('enrichment/hash-enrich')
    expect(cmd).toBeDefined()
    expect(cmd!.args).toHaveProperty('hash')
  })
})
```

**Step 2: Run test — FAIL**

**Step 3: Write the adapter**

```typescript
// src/adapters/_enrichment/hash-enrich.ts
import { cli, Strategy } from '../../registry.js'
import type { ExecContext } from '../../types.js'
import { loadAuth } from '../../auth/index.js'

interface SourceConfig {
  name: string
  provider: string
  url: (hash: string) => string
  method?: string
  headers: (key: string) => Record<string, string>
  body?: (hash: string) => unknown
  select?: string
  fields: Record<string, string>
}

const SOURCES: SourceConfig[] = [
  {
    name: 'VirusTotal',
    provider: 'virustotal',
    url: (h) => `https://www.virustotal.com/api/v3/files/${h}`,
    headers: (key) => ({ 'x-apikey': key, Accept: 'application/json' }),
    fields: {
      malicious: 'data.attributes.last_analysis_stats.malicious',
      file_type: 'data.attributes.type_description',
      name: 'data.attributes.meaningful_name',
    },
  },
  {
    name: 'MalwareBazaar',
    provider: 'abuse.ch',
    url: () => 'https://mb-api.abuse.ch/api/v1/',
    method: 'POST',
    headers: () => ({ 'Content-Type': 'application/x-www-form-urlencoded' }),
    body: (hash) => `query=lookup_hash&hash=${hash}`,
    select: 'data.0',
    fields: {
      signature: 'signature',
      file_type: 'file_type',
      first_seen: 'first_seen',
      tags: 'tags',
    },
  },
  {
    name: 'ThreatFox',
    provider: 'abuse.ch',
    url: () => 'https://threatfox-api.abuse.ch/api/v1/',
    method: 'POST',
    headers: () => ({ 'Content-Type': 'application/json' }),
    body: (hash) => ({ query: 'search_ioc', search_term: hash }),
    select: 'data.0',
    fields: {
      threat_type: 'threat_type',
      malware: 'malware_printable',
    },
  },
]

cli({
  provider: 'enrichment',
  name: 'hash-enrich',
  description: 'Enrich file hash from multiple sources in parallel',
  strategy: Strategy.FREE,
  args: {
    hash: { type: 'string', required: true, help: 'File hash (MD5, SHA1, or SHA256)' },
  },
  columns: ['source', 'status', 'detail'],

  async func(ctx: ExecContext, args: Record<string, unknown>): Promise<unknown> {
    const hash = args.hash as string
    const timeout = 15_000

    const activeSources = SOURCES.filter(s => {
      if (s.provider === 'abuse.ch') return true
      const creds = loadAuth(s.provider)
      return creds?.api_key != null
    })

    const results = await Promise.allSettled(
      activeSources.map(async (source) => {
        const creds = loadAuth(source.provider)
        const apiKey = creds?.api_key ?? ''

        const fetchOpts: RequestInit = {
          method: source.method ?? 'GET',
          headers: source.headers(apiKey),
          signal: AbortSignal.timeout(timeout),
        }

        if (source.body) {
          const body = source.body(hash)
          fetchOpts.body = typeof body === 'string' ? body : JSON.stringify(body)
        }

        const response = await fetch(source.url(hash), fetchOpts)
        if (!response.ok) {
          return { source: source.name, status: 'error', detail: `HTTP ${response.status}` }
        }

        const data = await response.json()
        let selected = data
        if (source.select) {
          selected = walkPath(data, source.select.split('.'))
        }

        const detail: string[] = []
        for (const [label, path] of Object.entries(source.fields)) {
          const val = walkPath(selected, path.split('.'))
          if (val !== undefined && val !== null) {
            const display = Array.isArray(val) ? val.join(', ') : String(val)
            detail.push(`${label}: ${display}`)
          }
        }

        return { source: source.name, status: 'ok', detail: detail.join(', ') || '-' }
      }),
    )

    return results.map((r, i) => {
      if (r.status === 'fulfilled') return r.value
      return { source: activeSources[i].name, status: 'error', detail: (r.reason as Error).message }
    })
  },
})

function walkPath(value: unknown, segments: string[]): unknown {
  for (const segment of segments) {
    if (value === null || value === undefined) return undefined
    if (Array.isArray(value) && /^\d+$/.test(segment)) {
      value = value[parseInt(segment, 10)]
    } else if (typeof value === 'object') {
      value = (value as Record<string, unknown>)[segment]
    } else {
      return undefined
    }
  }
  return value
}
```

**Step 4: Run test — PASS**

**Step 5: Commit**

```bash
git add src/adapters/_enrichment/hash-enrich.ts tests/adapter/hash-enrichment.test.ts
git commit -m "feat: add hash-enrich multi-source enrichment adapter"
```

---

### Task 3: Subprocess Pipeline Step

**Why:** Wrap local security tools (nmap, nuclei, etc.) via safe `execFile` — never string concat.

**Files:**
- Create: `src/pipeline/steps/subprocess.ts`
- Modify: `src/pipeline/executor.ts` — add `subprocess` case
- Test: `tests/unit/subprocess.test.ts`

**Step 1: Write the failing test**

```typescript
// tests/unit/subprocess.test.ts
import { describe, it, expect, vi } from 'vitest'
import { executeSubprocess } from '../../src/pipeline/steps/subprocess.js'

// Mock child_process
vi.mock('child_process', () => ({
  execFile: vi.fn((_cmd: string, _args: string[], _opts: any, cb: Function) => {
    cb(null, '{"host":"10.0.0.1","ports":[22,80,443]}', '')
  }),
}))

describe('subprocess step', () => {
  it('executes command with args array and parses JSON output', async () => {
    const result = await executeSubprocess(
      {
        command: 'nmap',
        args: ['-oJ', '-', '{{ args.target }}'],
        parse: 'json',
      },
      null,
      { args: { target: '10.0.0.1' }, auth: {} },
    )

    expect(result).toEqual({ host: '10.0.0.1', ports: [22, 80, 443] })
  })

  it('rejects shell operators in command', async () => {
    await expect(
      executeSubprocess(
        { command: 'nmap && rm -rf /', args: [], parse: 'json' },
        null,
        { args: {}, auth: {} },
      ),
    ).rejects.toThrow('shell operator')
  })

  it('rejects shell operators in args', async () => {
    await expect(
      executeSubprocess(
        { command: 'nmap', args: ['10.0.0.1; rm -rf /'], parse: 'lines' },
        null,
        { args: {}, auth: {} },
      ),
    ).rejects.toThrow('shell operator')
  })
})
```

**Step 2: Run test — FAIL**

**Step 3: Implement subprocess step**

```typescript
// src/pipeline/steps/subprocess.ts
import { execFile } from 'child_process'
import { PipelineError } from '../../errors.js'
import { renderTemplate } from '../template.js'

const SHELL_OPERATORS = /[;&|`$(){}[\]<>!\\]/

interface SubprocessParams {
  command: string
  args: string[]
  parse?: 'json' | 'lines' | 'text'
  timeout?: number
}

interface StepContext {
  args: Record<string, unknown>
  auth: Record<string, unknown>
}

export async function executeSubprocess(
  params: SubprocessParams,
  _data: unknown,
  ctx: StepContext,
): Promise<unknown> {
  const templateCtx = { args: ctx.args, auth: ctx.auth }

  // Security: validate command name
  const command = renderTemplate(params.command, templateCtx)
  if (SHELL_OPERATORS.test(command)) {
    throw new PipelineError('subprocess', `Rejected: shell operator in command "${command}"`)
  }

  // Security: validate each arg
  const args = params.args.map(arg => {
    const rendered = renderTemplate(arg, templateCtx)
    if (SHELL_OPERATORS.test(rendered)) {
      throw new PipelineError('subprocess', `Rejected: shell operator in arg "${rendered}"`)
    }
    return rendered
  })

  const timeoutMs = (params.timeout ?? 60) * 1000

  return new Promise((resolve, reject) => {
    execFile(command, args, { timeout: timeoutMs, maxBuffer: 10 * 1024 * 1024 }, (error, stdout, stderr) => {
      if (error) {
        reject(new PipelineError('subprocess', `${command} failed: ${error.message}${stderr ? ` (stderr: ${stderr.slice(0, 200)})` : ''}`))
        return
      }

      const output = stdout.trim()

      switch (params.parse ?? 'text') {
        case 'json':
          try {
            resolve(JSON.parse(output))
          } catch {
            reject(new PipelineError('subprocess', `Failed to parse JSON output from ${command}`))
          }
          break
        case 'lines':
          resolve(output.split('\n').filter(l => l.length > 0))
          break
        case 'text':
        default:
          resolve(output)
      }
    })
  })
}
```

**Step 4: Wire into executor**

In `src/pipeline/executor.ts`, add import:

```typescript
import { executeSubprocess } from './steps/subprocess.js'
```

Add case in `executeStep` switch:

```typescript
    case 'subprocess':
      return executeSubprocess(params as any, data, ctx)
```

**Step 5: Run test — PASS (3 tests)**

**Step 6: Commit**

```bash
git add src/pipeline/steps/subprocess.ts src/pipeline/executor.ts tests/unit/subprocess.test.ts
git commit -m "feat: add subprocess pipeline step with shell injection protection"
```

---

### Task 4: Shell Completion

**Files:**
- Modify: `src/cli.ts` — add `completion` command

**Step 1: Add completion command to cli.ts**

After the `doctor` command block in `src/cli.ts`, add:

```typescript
  // Built-in: completion
  program
    .command('completion <shell>')
    .description('Generate shell completion script (bash, zsh, fish)')
    .action((shell: string) => {
      const bin = 'opensec'
      switch (shell) {
        case 'bash':
          process.stdout.write(generateBashCompletion(bin, getRegistry()))
          break
        case 'zsh':
          process.stdout.write(generateZshCompletion(bin, getRegistry()))
          break
        case 'fish':
          process.stdout.write(generateFishCompletion(bin, getRegistry()))
          break
        default:
          process.stderr.write(`Unknown shell: ${shell}. Supported: bash, zsh, fish\n`)
          process.exit(EXIT_CODES.BAD_ARGUMENT)
      }
    })
```

Add these functions at the bottom of `src/cli.ts` (before `handleError`):

```typescript
function generateBashCompletion(bin: string, registry: Map<string, CliCommand>): string {
  const providers = [...new Set([...registry.values()].map(c => c.provider))]
  const commands = [...registry.values()].map(c => `${c.provider}/${c.name}`)
  return `# ${bin} bash completion
_${bin}_completions() {
  local cur prev providers
  cur="\${COMP_WORDS[COMP_CWORD]}"
  prev="\${COMP_WORDS[COMP_CWORD-1]}"
  providers="${providers.join(' ')}"

  case "\${prev}" in
    ${bin})
      COMPREPLY=( $(compgen -W "list auth doctor completion ${providers.join(' ')}" -- "\${cur}") )
      return 0
      ;;
${providers.map(p => {
  const cmds = [...registry.values()].filter(c => c.provider === p).map(c => c.name)
  return `    ${p})
      COMPREPLY=( $(compgen -W "${cmds.join(' ')}" -- "\${cur}") )
      return 0
      ;;`
}).join('\n')}
    auth)
      COMPREPLY=( $(compgen -W "add list test remove" -- "\${cur}") )
      return 0
      ;;
  esac
}
complete -F _${bin}_completions ${bin}
`
}

function generateZshCompletion(bin: string, registry: Map<string, CliCommand>): string {
  const providers = [...new Set([...registry.values()].map(c => c.provider))]
  return `#compdef ${bin}
_${bin}() {
  local -a commands
  commands=(
    'list:List all available commands'
    'auth:Manage API credentials'
    'doctor:Check environment'
    'completion:Generate shell completion'
${providers.map(p => `    '${p}:${p} commands'`).join('\n')}
  )
  _describe 'command' commands
}
_${bin} "$@"
`
}

function generateFishCompletion(bin: string, registry: Map<string, CliCommand>): string {
  const lines = [
    `# ${bin} fish completion`,
    `complete -c ${bin} -n "__fish_use_subcommand" -a "list" -d "List all commands"`,
    `complete -c ${bin} -n "__fish_use_subcommand" -a "auth" -d "Manage credentials"`,
    `complete -c ${bin} -n "__fish_use_subcommand" -a "doctor" -d "Check environment"`,
  ]
  const providers = [...new Set([...registry.values()].map(c => c.provider))]
  for (const p of providers) {
    lines.push(`complete -c ${bin} -n "__fish_use_subcommand" -a "${p}" -d "${p} commands"`)
    const cmds = [...registry.values()].filter(c => c.provider === p)
    for (const cmd of cmds) {
      lines.push(`complete -c ${bin} -n "__fish_seen_subcommand_from ${p}" -a "${cmd.name}" -d "${cmd.description}"`)
    }
  }
  return lines.join('\n') + '\n'
}
```

**Step 2: Manual test**

Run: `npx tsx src/main.ts completion bash | head -20`
Expected: Bash completion script with provider names

Run: `npx tsx src/main.ts completion zsh | head -20`
Expected: Zsh completion script

**Step 3: Commit**

```bash
git add src/cli.ts
git commit -m "feat: add shell completion (bash, zsh, fish)"
```

---

### Task 5: GitHub Actions CI

**Files:**
- Create: `.github/workflows/ci.yml`

**Step 1: Write the CI workflow**

```yaml
# .github/workflows/ci.yml
name: CI
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        node-version: [20, 22]
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: ${{ matrix.node-version }}
          cache: npm
      - run: npm ci
      - run: npm run typecheck
      - run: npx vitest run

  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 22
          cache: npm
      - run: npm ci
      - run: npm audit --omit=dev
```

**Step 2: Commit**

```bash
mkdir -p .github/workflows
git add .github/workflows/ci.yml
git commit -m "ci: add GitHub Actions (test matrix + security audit)"
```

---

### Task 6: GitHub Issue Templates

**Files:**
- Create: `.github/ISSUE_TEMPLATE/adapter-request.yml`
- Create: `.github/ISSUE_TEMPLATE/bug-report.yml`
- Create: `.github/PULL_REQUEST_TEMPLATE.md`

**Step 1: Write adapter request template**

```yaml
# .github/ISSUE_TEMPLATE/adapter-request.yml
name: Adapter Request
description: Request a new security API adapter
labels: ["adapter-request", "good first issue"]
body:
  - type: input
    id: provider
    attributes:
      label: API Provider
      placeholder: e.g., urlscan.io
    validations:
      required: true
  - type: input
    id: api_url
    attributes:
      label: API Documentation URL
      placeholder: https://urlscan.io/docs/api/
    validations:
      required: true
  - type: dropdown
    id: auth
    attributes:
      label: Authentication
      options:
        - No auth required (free)
        - Free API key (registration required)
        - Paid API key
    validations:
      required: true
  - type: textarea
    id: use_case
    attributes:
      label: Use Case
      description: What security task does this help with?
      placeholder: "I want to scan URLs for phishing indicators..."
    validations:
      required: true
  - type: checkboxes
    id: contribute
    attributes:
      label: Contribution
      options:
        - label: I'd like to implement this adapter myself
```

**Step 2: Write bug report template**

```yaml
# .github/ISSUE_TEMPLATE/bug-report.yml
name: Bug Report
description: Report a bug
labels: ["bug"]
body:
  - type: input
    id: command
    attributes:
      label: Command
      placeholder: opensec nvd cve-get CVE-2024-3094
    validations:
      required: true
  - type: textarea
    id: expected
    attributes:
      label: Expected Behavior
    validations:
      required: true
  - type: textarea
    id: actual
    attributes:
      label: Actual Behavior
    validations:
      required: true
  - type: input
    id: version
    attributes:
      label: OpenSecCLI Version
      placeholder: opensec --version
  - type: input
    id: node
    attributes:
      label: Node.js Version
      placeholder: node --version
```

**Step 3: Write PR template**

```markdown
<!-- .github/PULL_REQUEST_TEMPLATE.md -->
## What

<!-- One sentence: what does this PR do? -->

## Type

- [ ] New adapter
- [ ] Bug fix
- [ ] Feature
- [ ] Documentation

## Checklist

- [ ] Tests pass (`npx vitest run`)
- [ ] TypeScript compiles (`npm run typecheck`)
- [ ] New adapter has a test in `tests/adapter/`
- [ ] YAML adapter follows schema in CONTRIBUTING.md
```

**Step 4: Commit**

```bash
mkdir -p .github/ISSUE_TEMPLATE
git add .github/
git commit -m "chore: add GitHub issue templates + PR template"
```

---

### Task 7: Pre-seed Good First Issues

**Why:** 20+ "Adapter Request" issues are the primary contributor magnet. Each issue = one API to wrap = one YAML file to write.

**Files:** None (GitHub API calls)

**Step 1: Create issues via gh CLI**

Run each:

```bash
gh issue create --title "adapter: urlscan.io" --label "adapter-request,good first issue" --body "**Provider:** urlscan.io
**API Docs:** https://urlscan.io/docs/api/
**Auth:** Free API key
**Use Case:** URL scanning and phishing analysis
**Suggested commands:** scan (submit URL), result (get scan result)"

gh issue create --title "adapter: Censys" --label "adapter-request,good first issue" --body "**Provider:** Censys
**API Docs:** https://search.censys.io/api
**Auth:** Free API key
**Use Case:** Internet-wide scan data, exposed service search"

gh issue create --title "adapter: AlienVault OTX" --label "adapter-request,good first issue" --body "**Provider:** AlienVault OTX
**API Docs:** https://otx.alienvault.com/api
**Auth:** Free API key
**Use Case:** Threat intelligence pulses, IOC lookup"

gh issue create --title "adapter: PhishTank" --label "adapter-request,good first issue" --body "**Provider:** PhishTank
**API Docs:** https://phishtank.org/developer_info.php
**Auth:** Free API key
**Use Case:** Phishing URL verification"

gh issue create --title "adapter: SecurityTrails" --label "adapter-request,good first issue" --body "**Provider:** SecurityTrails
**API Docs:** https://securitytrails.com/corp/apidocs
**Auth:** Free API key (50/month)
**Use Case:** DNS history, subdomain enumeration"

gh issue create --title "adapter: Pulsedive" --label "adapter-request,good first issue" --body "**Provider:** Pulsedive
**API Docs:** https://pulsedive.com/api/
**Auth:** Free API key (30/day)
**Use Case:** Threat intel enrichment"

gh issue create --title "adapter: Hybrid Analysis" --label "adapter-request,good first issue" --body "**Provider:** Hybrid Analysis
**API Docs:** https://www.hybrid-analysis.com/docs/api/v2
**Auth:** Free API key
**Use Case:** Malware sandbox analysis"

gh issue create --title "adapter: CIRCL hashlookup" --label "adapter-request,good first issue" --body "**Provider:** CIRCL hashlookup
**API Docs:** https://www.circl.lu/services/hashlookup/
**Auth:** No auth required
**Use Case:** Hash lookup against NSRL and other databases"

gh issue create --title "adapter: EmailRep.io" --label "adapter-request,good first issue" --body "**Provider:** EmailRep.io
**API Docs:** https://emailrep.io/docs
**Auth:** Free tier
**Use Case:** Email reputation scoring"

gh issue create --title "adapter: MaxMind GeoLite2" --label "adapter-request,good first issue" --body "**Provider:** MaxMind GeoLite2
**API Docs:** https://dev.maxmind.com/geoip/docs/web-services
**Auth:** Free license key
**Use Case:** IP geolocation database"
```

Note: This task requires `gh` CLI to be authenticated. If `gh auth status` fails, skip this task and create issues manually via GitHub web UI.

**Step 2: Verify**

Run: `gh issue list --limit 10`

**Step 3: No commit needed (issues are on GitHub)**

---

### Task 8: Final Verification

**Step 1: Run full test suite**

Run: `npx vitest run`
Expected: All tests PASS

**Step 2: Verify adapter count**

Run: `npx tsx src/main.ts list --json 2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d), 'adapters')"`
Expected: `18 adapters` (16 + domain-enrich + hash-enrich)

**Step 3: Test shell completion**

Run: `npx tsx src/main.ts completion bash | head -5`
Expected: Bash completion script header

**Step 4: Verify doctor**

Run: `npx tsx src/main.ts doctor`
Expected: Version, node, 18 adapters, auth count

**Step 5: Commit + push**

```bash
git add -A && git status
# If clean, push:
git push origin main
```

---

## Summary

| Task | What | Files | Tests |
|------|------|-------|-------|
| 1 | Domain enrichment adapter | `_enrichment/domain-enrich.ts` | 1 |
| 2 | Hash enrichment adapter | `_enrichment/hash-enrich.ts` | 1 |
| 3 | Subprocess pipeline step | `pipeline/steps/subprocess.ts` | 3 |
| 4 | Shell completion (bash/zsh/fish) | `cli.ts` | manual |
| 5 | GitHub Actions CI | `.github/workflows/ci.yml` | - |
| 6 | Issue + PR templates | `.github/ISSUE_TEMPLATE/*` | - |
| 7 | Pre-seed 10 good-first-issues | GitHub API | - |
| 8 | Final verification | - | all |

**Total: 8 tasks, ~7 commits, 2 new TS adapters, 1 new pipeline step, ~5 new tests, CI + templates**
