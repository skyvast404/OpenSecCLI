# P1 Error Handling, Tool Versioning & Testing Hardening Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Standardize tool-not-found errors across all adapters, add tool version checking, add manifest round-trip test, and add integration tests for adapter `func()` flows.

**Architecture:** `ToolNotFoundError` already exists in `src/errors.ts` but nobody uses it — wire it into `tool-runner.ts` so all 24 tool-wrapping adapters get consistent error handling for free. Add `getToolVersion()` to tool-runner. Add integration tests that mock `execFile` to verify full adapter flows.

**Tech Stack:** TypeScript, Vitest, node:child_process mock

---

## Task 1: Wire `ToolNotFoundError` into tool-runner

`src/errors.ts:47-55` already has `ToolNotFoundError(tool, installHint)`. The execution engine in `src/execution.ts` catches `CliError` subclasses and renders them with icons. But `tool-runner.ts:148-152` and 9 adapters throw raw `new Error()` — these bypass the error rendering system.

**Files:**
- Modify: `src/adapters/_utils/tool-runner.ts:148-152`
- Test: `tests/unit/tool-runner.test.ts`

**Step 1: Write the failing test**

```typescript
// Add to tests/unit/tool-runner.test.ts
import { ToolNotFoundError } from '../../src/errors.js'

describe('runExternalTool', () => {
  it('throws ToolNotFoundError when no tools available', async () => {
    await expect(
      runExternalTool({
        tools: ['nonexistent_tool_xyz_99999'],
        buildArgs: () => [],
        parseOutput: () => [],
      }),
    ).rejects.toBeInstanceOf(ToolNotFoundError)
  })
})
```

**Step 2: Run test — expect FAIL** (currently throws plain Error, not ToolNotFoundError)

Run: `npx vitest run tests/unit/tool-runner.test.ts`

**Step 3: Fix `tool-runner.ts`**

Add import at top:
```typescript
import { ToolNotFoundError } from '../../errors.js'
```

Replace lines 148-152 in `runExternalTool`:
```typescript
  const tool = await findAvailableTool(opts.tools)
  if (!tool) {
    throw new ToolNotFoundError(
      opts.tools.join(', '),
      opts.tools.length === 1
        ? opts.tools[0]
        : `one of: ${opts.tools.join(', ')}`,
    )
  }
```

**Step 4: Run test — expect PASS**

**Step 5: Remove redundant error throws from 9 adapters**

These adapters throw their own "not installed" errors BEFORE calling `runExternalTool` (which now handles it). Remove the duplicate checks:

- `src/adapters/vuln/nuclei-scan.ts` — remove `if (!checkToolInstalled('nuclei')) throw ...`, use `runExternalTool` instead of `checkToolInstalled` + `runTool`
- `src/adapters/vuln/nikto-scan.ts` — same
- `src/adapters/secrets/trufflehog-scan.ts` — same

For adapters already using `runExternalTool` (recon/, cloud/, supply-chain/sbom), their manual error messages become unnecessary since `runExternalTool` now throws `ToolNotFoundError`. But the error messages from `runExternalTool` are generic. To preserve good install hints, add an optional `installHint` field to the `runExternalTool` options:

```typescript
export async function runExternalTool(opts: {
  tools: string[]
  buildArgs: (tool: string) => string[]
  installHint?: string  // NEW
  // ... rest unchanged
}): Promise<{ tool: string; results: Record<string, unknown>[] }> {
  const tool = await findAvailableTool(opts.tools)
  if (!tool) {
    throw new ToolNotFoundError(
      opts.tools.join(', '),
      opts.installHint ?? opts.tools.join(' or '),
    )
  }
  // ... rest unchanged
}
```

Then update adapters that have good install hints:
- `nuclei-scan.ts`: `installHint: 'go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest'`
- `nikto-scan.ts`: `installHint: 'apt install nikto / brew install nikto'`
- `trufflehog-scan.ts`: `installHint: 'brew install trufflehog'`

For adapters already using `findAvailableTool` + manual `throw new Error(...)`:
- `recon/tech-fingerprint.ts` — replace `throw new Error(...)` with `throw new ToolNotFoundError(...)`
- `recon/content-discover.ts` — same
- `recon/port-scan.ts` — same
- `vuln/tls-check.ts` — same
- `vuln/api-discover.ts` — same
- `supply-chain/sbom.ts` — same

**Step 6: Commit**

```bash
git add src/adapters/_utils/tool-runner.ts src/adapters/vuln/ src/adapters/recon/ src/adapters/secrets/ src/adapters/supply-chain/sbom.ts tests/unit/tool-runner.test.ts
git commit -m "refactor: use ToolNotFoundError across all tool-wrapping adapters"
```

---

## Task 2: Add `getToolVersion()` to tool-runner

**Files:**
- Modify: `src/adapters/_utils/tool-runner.ts`
- Test: `tests/unit/tool-runner.test.ts`

**Step 1: Write the failing test**

```typescript
describe('getToolVersion', () => {
  it('returns version string for installed tool', async () => {
    const version = await getToolVersion('node')
    expect(version).toMatch(/^\d+\.\d+/)
  })

  it('returns null for missing tool', async () => {
    const version = await getToolVersion('nonexistent_tool_xyz_99999')
    expect(version).toBeNull()
  })
})
```

**Step 2: Run test — FAIL**

**Step 3: Implement**

Add to `src/adapters/_utils/tool-runner.ts`:

```typescript
/**
 * Get the version string of an installed tool.
 * Tries --version, -v, -V, version in order.
 */
export async function getToolVersion(tool: string): Promise<string | null> {
  const versionFlags = ['--version', '-v', '-V', 'version']
  for (const flag of versionFlags) {
    try {
      const result = await runTool({
        tool,
        args: [flag],
        timeout: 5,
        allowNonZero: true,
      })
      const output = (result.stdout + result.stderr).trim()
      // Extract first version-like pattern
      const match = output.match(/(\d+\.\d+[\w.-]*)/)
      if (match) return match[1]
    } catch {
      continue
    }
  }
  return null
}
```

**Step 4: Run test — PASS**

**Step 5: Commit**

```bash
git add src/adapters/_utils/tool-runner.ts tests/unit/tool-runner.test.ts
git commit -m "feat: add getToolVersion() utility for external tool version detection"
```

---

## Task 3: Add manifest round-trip test

Verify: build manifest → load via discovery → all commands register correctly. This prevents regressions like the `_enrichment` duplicate bug.

**Files:**
- Create: `tests/unit/manifest.test.ts`

**Step 1: Write test**

```typescript
// tests/unit/manifest.test.ts
import { describe, it, expect } from 'vitest'
import { readFileSync, existsSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const __dirname = dirname(fileURLToPath(import.meta.url))
const ROOT = join(__dirname, '..', '..')

describe('cli-manifest', () => {
  // This test runs against the source adapters, not dist
  it('build-manifest produces valid JSON with all adapters', async () => {
    // Import build-manifest logic would require build. Instead, verify
    // the existing manifest if dist exists.
    const manifestPath = join(ROOT, 'dist', 'cli-manifest.json')
    if (!existsSync(manifestPath)) return // skip if no build

    const manifest = JSON.parse(readFileSync(manifestPath, 'utf-8')) as Array<{
      provider: string
      name: string
      source: string
      modulePath?: string
    }>

    expect(manifest.length).toBeGreaterThanOrEqual(40)

    // No duplicate keys
    const keys = manifest.map(e => `${e.provider}/${e.name}`)
    const uniqueKeys = new Set(keys)
    expect(uniqueKeys.size).toBe(keys.length)

    // No provider starts with underscore
    for (const entry of manifest) {
      expect(entry.provider).not.toMatch(/^_/)
    }

    // Every TS adapter has a modulePath
    for (const entry of manifest) {
      if (entry.source === 'typescript') {
        expect(entry.modulePath).toBeTruthy()
      }
    }

    // Known providers exist
    const providers = new Set(manifest.map(e => e.provider))
    expect(providers.has('scan')).toBe(true)
    expect(providers.has('recon')).toBe(true)
    expect(providers.has('vuln')).toBe(true)
    expect(providers.has('enrichment')).toBe(true)
  })

  it('every TS adapter file has a cli() registration', () => {
    // Walk src/adapters and verify every .ts file (except parsers, types, _utils)
    // contains a cli({ call
    const { readdirSync, statSync } = require('node:fs')
    const adaptersDir = join(ROOT, 'src', 'adapters')
    const providers = readdirSync(adaptersDir, { withFileTypes: true })
      .filter((d: any) => d.isDirectory() && d.name !== '_utils')

    for (const provider of providers) {
      const dir = join(adaptersDir, provider.name)
      const files = readdirSync(dir)
        .filter((f: string) => f.endsWith('.ts') && !f.endsWith('.test.ts') && !f.endsWith('.d.ts'))
        .filter((f: string) => !['types.ts', 'parsers.ts'].includes(f))

      for (const file of files) {
        const content = readFileSync(join(dir, file), 'utf-8')
        if (!content.includes('cli(')) {
          // parsers/types files are OK without cli() — but we already filtered them
          throw new Error(`${provider.name}/${file} does not contain a cli() registration`)
        }
      }
    }
  })
})
```

**Step 2: Run test**

Run: `npx vitest run tests/unit/manifest.test.ts`
Expected: PASS (manifest exists from previous build)

**Step 3: Commit**

```bash
git add tests/unit/manifest.test.ts
git commit -m "test: add manifest round-trip and adapter registration tests"
```

---

## Task 4: Add integration tests for adapter `func()` flows

Mock `execFile` to test the full adapter lifecycle: args → tool check → spawn → parse → return.

**Files:**
- Create: `tests/integration/adapter-func.test.ts`

**Step 1: Write tests**

```typescript
// tests/integration/adapter-func.test.ts
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import * as childProcess from 'node:child_process'

// Mock execFile at the module level
vi.mock('node:child_process', async () => {
  const actual = await vi.importActual<typeof childProcess>('node:child_process')
  return {
    ...actual,
    execFile: vi.fn(),
  }
})

const mockExecFile = vi.mocked(childProcess.execFile)

// Helper to make execFile resolve with stdout
function mockToolOutput(tool: string, stdout: string) {
  mockExecFile.mockImplementation(((cmd: string, args: string[], opts: any, cb: any) => {
    if (typeof opts === 'function') {
      cb = opts
      opts = {}
    }
    // 'which' check — return success for the requested tool
    if (cmd === 'which') {
      cb(null, `/usr/bin/${args[0]}`, '')
      return { stdin: { end: vi.fn() } }
    }
    // Actual tool execution
    if (cmd === tool) {
      cb(null, stdout, '')
      return { stdin: { end: vi.fn() } }
    }
    cb(new Error(`unexpected call: ${cmd}`), '', '')
    return { stdin: { end: vi.fn() } }
  }) as any)
}

describe('adapter func() integration', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('scan/analyze: semgrep produces findings', async () => {
    const semgrepOutput = JSON.stringify({
      results: [{
        check_id: 'javascript.express.security.audit.xss',
        path: 'src/app.js',
        start: { line: 42 },
        extra: {
          severity: 'WARNING',
          message: 'Potential XSS',
          metadata: { cwe: ['CWE-79'] },
        },
      }],
    })

    mockToolOutput('semgrep', semgrepOutput)

    // Import after mock is set up
    const { getRegistry } = await import('../../src/registry.js')

    // Need to trigger adapter registration
    await import('../../src/adapters/scan/analyze.js')

    const cmd = getRegistry().get('scan/analyze')
    expect(cmd).toBeTruthy()

    const mockCtx = {
      auth: null,
      args: {},
      log: {
        info: vi.fn(),
        warn: vi.fn(),
        error: vi.fn(),
        verbose: vi.fn(),
        debug: vi.fn(),
        step: vi.fn(),
      },
    }

    const result = await cmd!.func!(mockCtx, { path: '/tmp/test', tools: 'semgrep' })
    expect(Array.isArray(result)).toBe(true)
    const findings = result as Array<Record<string, unknown>>
    expect(findings.length).toBe(1)
    expect(findings[0].rule_id).toBe('javascript.express.security.audit.xss')
    expect(findings[0].severity).toBe('medium')
    expect(findings[0].cwe).toBe('CWE-79')
  })

  it('crypto/hash-id: identifies SHA-256 without mocking', async () => {
    // Pure TS adapter — no mock needed
    await import('../../src/adapters/crypto/hash-id.js')
    const { getRegistry } = await import('../../src/registry.js')

    const cmd = getRegistry().get('crypto/hash-id')
    expect(cmd).toBeTruthy()

    const mockCtx = {
      auth: null, args: {},
      log: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), verbose: vi.fn(), debug: vi.fn(), step: vi.fn() },
    }

    const result = await cmd!.func!(mockCtx, {
      hash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    })
    const findings = result as Array<Record<string, unknown>>
    expect(findings.some(f => f.algorithm === 'SHA-256')).toBe(true)
  })

  it('supply-chain/ci-audit: detects unpinned actions', async () => {
    // Pure TS adapter — writes a temp workflow file
    const { mkdtempSync, mkdirSync, writeFileSync, rmSync } = await import('node:fs')
    const { join } = await import('node:path')
    const tmpDir = mkdtempSync('/tmp/opensec-test-')
    const ghDir = join(tmpDir, '.github', 'workflows')
    mkdirSync(ghDir, { recursive: true })
    writeFileSync(join(ghDir, 'ci.yml'), `
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@main
      - run: echo "Hello \${{ github.event.pull_request.title }}"
`)

    try {
      await import('../../src/adapters/supply-chain/ci-audit.js')
      const { getRegistry } = await import('../../src/registry.js')

      const cmd = getRegistry().get('supply-chain/ci-audit')
      const mockCtx = {
        auth: null, args: {},
        log: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), verbose: vi.fn(), debug: vi.fn(), step: vi.fn() },
      }

      const result = await cmd!.func!(mockCtx, { path: tmpDir })
      const findings = result as Array<Record<string, unknown>>
      expect(findings.length).toBeGreaterThanOrEqual(2) // unpinned + expression injection
      expect(findings.some(f => f.rule === 'unpinned-action')).toBe(true)
      expect(findings.some(f => f.rule === 'expression-injection')).toBe(true)
    } finally {
      rmSync(tmpDir, { recursive: true })
    }
  })
})
```

**Step 2: Run tests**

Run: `npx vitest run tests/integration/adapter-func.test.ts`
Expected: PASS

Note: The `scan/analyze` test with mocked execFile may need adjustments based on how vitest handles ESM mocking. If the mock doesn't work with ESM imports, simplify to just test pure-TS adapters (crypto/hash-id, supply-chain/ci-audit, vuln/header-audit, vuln/cors-check) which don't need mocks.

**Step 3: Commit**

```bash
git add tests/integration/adapter-func.test.ts
git commit -m "test: add integration tests for adapter func() flows"
```

---

## Task 5: Final verification

**Step 1: Clean build**

```bash
rm -rf dist && npx tsc --incremental false && npm run copy-yaml && npm run build-manifest
```

Expected: 46 adapters

**Step 2: Full test suite**

```bash
npx vitest run
```

Expected: All pass

**Step 3: Smoke test**

```bash
node dist/main.js crypto hash-id --hash 5d41402abc4b2a76b9719d911017c592
node dist/main.js vuln header-audit --url https://example.com --format json | head -5
node dist/main.js recon subdomain-enum --domain example.com 2>&1 | head -3
```

Expected: hash-id works, header-audit works, subdomain-enum shows ToolNotFoundError with icon

**Step 4: Commit & push**

```bash
git add -A
git commit -m "chore: verify P1 hardening complete"
git push origin main
```

---

## Summary

| Task | What | Lines changed (est.) |
|------|------|---------------------|
| 1 | `ToolNotFoundError` in tool-runner + 9 adapter fixes | ~30 changed |
| 2 | `getToolVersion()` utility | ~30 added |
| 3 | Manifest round-trip test | ~60 added |
| 4 | Integration tests for adapter func() | ~100 added |
| 5 | Final verification | 0 |

## Unresolved Questions

1. Should `getToolVersion` be called lazily (on first use) or eagerly (during discovery)? Lazy is simpler and doesn't slow startup.
2. The `scan/analyze` integration test with mocked `execFile` may be fragile with ESM. If it is, fall back to testing only pure-TS adapters in integration tests.
