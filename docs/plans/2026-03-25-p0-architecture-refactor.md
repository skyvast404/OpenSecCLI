# P0 Architecture Refactor Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Eliminate code duplication, unify tool-runner infrastructure, resolve functional overlap between `scan/analyze` and `supply-chain/dep-audit`.

**Architecture:** Extract 3 shared utilities (`walkPath`, `walkDir`, `SKIP_DIRS`), migrate `scan/analyze.ts` and `scan/full.ts` to use `_utils/tool-runner.ts`, remove npm-audit/pip-audit from `scan/analyze` (they belong in `supply-chain/dep-audit`), rename `_enrichment` → `enrichment`.

**Tech Stack:** TypeScript, Vitest, node:child_process

---

## Task 1: Extract `walkPath` to shared utility

3 copies exist: `pipeline/template.ts:133`, `pipeline/steps/enrich.ts:83`, `_enrichment/ip-enrich.ts:173`. The `enrich.ts` version is the most complete (handles array indices).

**Files:**
- Create: `src/utils/walk-path.ts`
- Modify: `src/pipeline/template.ts:133-143` — delete local `walkPath`, import from `../utils/walk-path.js`
- Modify: `src/pipeline/steps/enrich.ts:83-95` — delete local `walkPath`, import from `../../utils/walk-path.js`
- Modify: `src/adapters/_enrichment/ip-enrich.ts:173-185` — delete local `walkPath`, import from `../../utils/walk-path.js`
- Create: `tests/unit/walk-path.test.ts`

**Step 1: Write the failing test**

```typescript
// tests/unit/walk-path.test.ts
import { describe, it, expect } from 'vitest'
import { walkPath } from '../../src/utils/walk-path.js'

describe('walkPath', () => {
  it('resolves nested object paths', () => {
    const obj = { a: { b: { c: 42 } } }
    expect(walkPath(obj, ['a', 'b', 'c'])).toBe(42)
  })

  it('resolves array indices', () => {
    const obj = { items: [{ name: 'first' }, { name: 'second' }] }
    expect(walkPath(obj, ['items', '1', 'name'])).toBe('second')
  })

  it('returns undefined for missing keys', () => {
    const obj = { a: { b: 1 } }
    expect(walkPath(obj, ['a', 'x', 'y'])).toBeUndefined()
  })

  it('returns undefined for null/undefined in chain', () => {
    expect(walkPath(null, ['a'])).toBeUndefined()
    expect(walkPath(undefined, ['a'])).toBeUndefined()
  })

  it('returns root value for empty segments', () => {
    expect(walkPath(42, [])).toBe(42)
  })
})
```

**Step 2: Run test to verify it fails**

Run: `npx vitest run tests/unit/walk-path.test.ts`
Expected: FAIL — module not found

**Step 3: Create shared module**

```typescript
// src/utils/walk-path.ts
/**
 * Traverse a nested object/array by dot-separated path segments.
 * Handles numeric segments as array indices.
 */
export function walkPath(value: unknown, segments: string[]): unknown {
  let current = value
  for (const seg of segments) {
    if (current == null || typeof current !== 'object') return undefined
    if (Array.isArray(current)) {
      const idx = Number(seg)
      current = Number.isNaN(idx) ? undefined : current[idx]
    } else {
      current = (current as Record<string, unknown>)[seg]
    }
  }
  return current
}
```

**Step 4: Replace 3 local copies**

In `src/pipeline/template.ts`:
- Add `import { walkPath } from '../utils/walk-path.js'` at top
- Delete lines 133-143 (local `walkPath` function)

In `src/pipeline/steps/enrich.ts`:
- Add `import { walkPath } from '../../utils/walk-path.js'` at top
- Delete lines 83-95 (local `walkPath` function)

In `src/adapters/_enrichment/ip-enrich.ts`:
- Add `import { walkPath } from '../../utils/walk-path.js'` at top
- Delete lines 173-185 (local `walkPath` function)

**Step 5: Run all tests**

Run: `npx vitest run --project unit`
Expected: All pass (new + existing)

**Step 6: Commit**

```bash
git add src/utils/walk-path.ts tests/unit/walk-path.test.ts src/pipeline/template.ts src/pipeline/steps/enrich.ts src/adapters/_enrichment/ip-enrich.ts
git commit -m "refactor: extract walkPath to shared utility, remove 3 duplicates"
```

---

## Task 2: Extract `walkDir` + `SKIP_DIRS` to shared utility

2 copies: `scan/entrypoints.ts:196-224` (`walkDir`), `scan/discover.ts:48-118` (`walkSourceFiles`). Same logic, different extension sets.

**Files:**
- Create: `src/utils/fs-walk.ts`
- Modify: `src/adapters/scan/entrypoints.ts` — delete local `walkDir` + `SKIP_DIRS` + `SCAN_EXTENSIONS`, import from `../../utils/fs-walk.js`
- Modify: `src/adapters/scan/discover.ts` — delete local `walkSourceFiles` + `SKIP_DIRS` + `SOURCE_EXTENSIONS`, import from `../../utils/fs-walk.js`
- Create: `tests/unit/fs-walk.test.ts`

**Step 1: Write the failing test**

```typescript
// tests/unit/fs-walk.test.ts
import { describe, it, expect } from 'vitest'
import { SKIP_DIRS, walkDir } from '../../src/utils/fs-walk.js'

describe('fs-walk', () => {
  it('SKIP_DIRS contains expected entries', () => {
    expect(SKIP_DIRS.has('node_modules')).toBe(true)
    expect(SKIP_DIRS.has('.git')).toBe(true)
    expect(SKIP_DIRS.has('dist')).toBe(true)
  })

  it('walkDir finds files matching extensions', async () => {
    // Walk the src/utils directory itself — should find .ts files
    const files = await walkDir('src/utils', { extensions: new Set(['.ts']), maxDepth: 1 })
    expect(files.length).toBeGreaterThan(0)
    expect(files.every(f => f.endsWith('.ts'))).toBe(true)
  })

  it('walkDir respects maxDepth=0', async () => {
    const files = await walkDir('src', { extensions: new Set(['.ts']), maxDepth: 0 })
    // maxDepth 0 means no recursion — only files in src/ directly
    expect(files.every(f => !f.includes('/adapters/'))).toBe(true)
  })
})
```

**Step 2: Run test to verify it fails**

Run: `npx vitest run tests/unit/fs-walk.test.ts`
Expected: FAIL

**Step 3: Create shared module**

```typescript
// src/utils/fs-walk.ts
/**
 * Shared filesystem walk utility.
 * Replaces duplicated walkDir/walkSourceFiles in scan adapters.
 */

import { readdirSync, statSync } from 'node:fs'
import { join, extname } from 'node:path'

export const SKIP_DIRS = new Set([
  'node_modules', '.git', '__pycache__', '.venv', 'venv',
  'dist', 'build', '.next', 'vendor', 'target',
])

export interface WalkOptions {
  extensions: Set<string>
  maxDepth?: number
  skipDirs?: Set<string>
}

export async function walkDir(
  dir: string,
  opts: WalkOptions,
  depth = 0,
): Promise<string[]> {
  const maxDepth = opts.maxDepth ?? 10
  const skipDirs = opts.skipDirs ?? SKIP_DIRS

  if (depth > maxDepth) return []

  const results: string[] = []
  try {
    const entries = readdirSync(dir, { withFileTypes: true })
    for (const entry of entries) {
      if (entry.name.startsWith('.') && entry.name !== '.github') continue
      const fullPath = join(dir, entry.name)

      if (entry.isDirectory()) {
        if (skipDirs.has(entry.name)) continue
        const sub = await walkDir(fullPath, opts, depth + 1)
        results.push(...sub)
      } else if (entry.isFile()) {
        if (opts.extensions.has(extname(entry.name))) {
          results.push(fullPath)
        }
      }
    }
  } catch {
    // Directory not readable — skip silently
  }
  return results
}
```

**Step 4: Replace local copies in entrypoints.ts and discover.ts**

In `src/adapters/scan/entrypoints.ts`:
- Add `import { walkDir, SKIP_DIRS } from '../../utils/fs-walk.js'` at top
- Keep `SCAN_EXTENSIONS` constant (specific to this adapter)
- Delete the local `SKIP_DIRS` (lines ~196-199)
- Replace local `walkDir` function (lines ~201-224) with a thin wrapper that passes `SCAN_EXTENSIONS`:
  ```typescript
  import { walkDir as walkDirBase } from '../../utils/fs-walk.js'
  // In the func body, replace:
  //   const files = await walkDir(projectPath)
  // with:
  //   const files = await walkDirBase(projectPath, { extensions: SCAN_EXTENSIONS })
  ```

In `src/adapters/scan/discover.ts`:
- Same pattern: import `walkDir` from `../../utils/fs-walk.js`, delete local `walkSourceFiles` + `SKIP_DIRS` + `SOURCE_EXTENSIONS`
- Use: `walkDir(projectPath, { extensions: SOURCE_EXTENSIONS })` where `SOURCE_EXTENSIONS` stays local to discover.ts

**Step 5: Run tests**

Run: `npx vitest run --project unit`
Expected: All pass

**Step 6: Commit**

```bash
git add src/utils/fs-walk.ts tests/unit/fs-walk.test.ts src/adapters/scan/entrypoints.ts src/adapters/scan/discover.ts
git commit -m "refactor: extract walkDir + SKIP_DIRS to shared utility, remove 2 duplicates"
```

---

## Task 3: Migrate `scan/analyze.ts` to use `_utils/tool-runner.ts`

Currently `scan/analyze.ts` has its own `checkTool()`, `execFileAsync`, and 4 per-tool runner functions. Migrate to shared `tool-runner.ts` which has the `child.stdin.end()` fix.

**Files:**
- Modify: `src/adapters/scan/analyze.ts`
- Test: `tests/unit/scan-analyze.test.ts` (existing — verify still passes)

**Step 1: Refactor tool runners in `scan/analyze.ts`**

Replace lines 10-13 (imports) and 127-134 (checkTool) with:
```typescript
import { checkToolInstalled, runTool } from '../_utils/tool-runner.js'
```

Delete the local `const execFileAsync` and `checkTool` function.

Rewrite `runSemgrep`, `runGitleaks`, `runNpmAudit`, `runPipAudit` to use `runTool()`:

```typescript
async function runSemgrep(
  repoPath: string,
  ctx: ExecContext,
): Promise<{ findings: RawFinding[]; metric: PhaseMetric }> {
  const start = Date.now()
  try {
    const result = await runTool({
      tool: 'semgrep',
      args: ['scan', '--json', '--config', 'auto', repoPath],
      timeout: 120,
    })
    const output = JSON.parse(result.stdout)
    const findings = parseSemgrepOutput(output)
    return {
      findings,
      metric: { adapter: 'semgrep', latency_ms: Date.now() - start, findings_count: findings.length, status: 'completed' },
    }
  } catch (error) {
    ctx.log.warn(`Semgrep failed: ${(error as Error).message}`)
    return {
      findings: [],
      metric: { adapter: 'semgrep', latency_ms: Date.now() - start, findings_count: 0, status: 'failed', error: (error as Error).message },
    }
  }
}
```

Same pattern for `runGitleaks` (use `allowNonZero: true` since gitleaks exits 1 on findings), `runNpmAudit` (use `allowNonZero: true`, `cwd: repoPath`), `runPipAudit`.

Also replace `checkTool(t)` calls in `func()` with `checkToolInstalled(t)`.

**Step 2: Remove npm-audit and pip-audit from `scan/analyze`**

This is the overlap fix. `scan/analyze` should focus on **SAST** (semgrep, gitleaks). Dependency auditing belongs in `supply-chain/dep-audit`.

- Delete `runNpmAudit()` function entirely
- Delete `runPipAudit()` function entirely
- Delete `parseNpmAuditOutput()` and `parsePipAuditOutput()` exports
- Remove `'npm'` and `'pip-audit'` from `toolNames` array
- Update description: `'Run static security analysis (semgrep, gitleaks) on a codebase'`
- Update `tools` arg help: `'Comma-separated tools: semgrep,gitleaks (default: auto-detect)'`

**Important:** Keep the `parseNpmAuditOutput` and `parsePipAuditOutput` functions exported because they are imported by `scan/full.ts`. Move them to a separate parsers file or keep them but mark them as deprecated. Actually — check if `scan/full.ts` uses them. Looking at the code: `full.ts` imports `parseNpmAuditOutput` from `./analyze.js` but does NOT use it in its current code (it only runs semgrep and gitleaks). So we can safely remove the npm/pip functions.

Wait — `full.ts` line 14 imports `parseNpmAuditOutput` but doesn't use it. So removing the export is safe. Actually, let me check: `full.ts` imports:
```typescript
import {
  parseSemgrepOutput,
  parseGitleaksOutput,
  parseNpmAuditOutput,  // imported but NOT USED in current code
  normalizeFindings,
  deduplicateFindings,
} from './analyze.js'
```

So: remove the unused import from `full.ts` as well.

**Step 3: Run tests**

Run: `npx vitest run tests/unit/scan-analyze.test.ts`
Expected: Some tests will fail because they test `parseNpmAuditOutput` and `parsePipAuditOutput`.

Update `tests/unit/scan-analyze.test.ts`:
- Remove tests for `parseNpmAuditOutput` and `parsePipAuditOutput`
- OR move those tests to `tests/unit/supply-chain.test.ts` (the parsers still exist in `supply-chain/dep-audit.ts`)

Actually, the parsers in `supply-chain/dep-audit.ts` are inline (not exported). The `scan/analyze.ts` parsers were exported and tested. The simplest approach: keep the parser functions in `scan/analyze.ts` but remove the runner functions. The parsers are still useful for `scan/full.ts` if it needs them later.

Better approach: just remove them. `supply-chain/dep-audit.ts` has its own inline parsing. No code outside `scan/` imports them.

**Step 4: Run full test suite**

Run: `npx vitest run --project unit`
Expected: All pass

**Step 5: Commit**

```bash
git add src/adapters/scan/analyze.ts tests/unit/scan-analyze.test.ts
git commit -m "refactor(scan): migrate analyze.ts to shared tool-runner, remove npm/pip-audit overlap"
```

---

## Task 4: Migrate `scan/full.ts` to call `scan/analyze` instead of copy-pasting

Currently `scan/full.ts` copy-pastes the semgrep/gitleaks invocation logic. It should import and call `scan/analyze`'s registered command instead.

**Files:**
- Modify: `src/adapters/scan/full.ts`

**Step 1: Refactor `scan/full.ts`**

Replace lines 20-23 (execFile imports) and 46-53 (toolExists) and 82-115 (copy-pasted tool runners) with a call to the analyze command via the registry:

```typescript
import { getRegistry } from '../../registry.js'

// In func(), replace Stage 2 analysis block with:
const analyzeCmd = getRegistry().get('scan/analyze')
if (analyzeCmd?.func) {
  const analyzeResult = await analyzeCmd.func(ctx, { path: repoPath, tools: 'auto' })
  if (Array.isArray(analyzeResult)) {
    // analyzeResult is already deduplicated RawFinding[]
    for (const r of analyzeResult) {
      allFindings.push({
        rule_id: (r as Record<string, unknown>).rule_id as string ?? '',
        severity: (r as Record<string, unknown>).severity as Severity ?? 'medium',
        message: (r as Record<string, unknown>).message as string ?? '',
        file_path: (r as Record<string, unknown>).file_path as string ?? '',
        start_line: (r as Record<string, unknown>).start_line as number ?? 0,
        cwe: (r as Record<string, unknown>).cwe as string ?? '',
        tools_used: ((r as Record<string, unknown>).tools_used as string ?? '').split(', '),
      })
    }
  }
}
```

Remove: `execFile`, `promisify`, `execFileAsync`, `toolExists`, the inline semgrep/gitleaks IIFEs, `parseNpmAuditOutput` import.

**Step 2: Run tests**

Run: `npx vitest run tests/unit/scan-full.test.ts`
Expected: PASS

**Step 3: Commit**

```bash
git add src/adapters/scan/full.ts
git commit -m "refactor(scan): full.ts delegates to scan/analyze instead of copy-pasting tool invocations"
```

---

## Task 5: Rename `_enrichment` → `enrichment`

**Files:**
- Rename: `src/adapters/_enrichment/` → `src/adapters/enrichment/`
- Modify: `src/adapters/enrichment/ip-enrich.ts` — update import path for `walkPath` if needed

**Step 1: Rename directory**

```bash
mv src/adapters/_enrichment src/adapters/enrichment
```

**Step 2: Update imports in ip-enrich.ts**

The `walkPath` import was added in Task 1. After rename, the relative path stays the same (`../../utils/walk-path.js`), so no change needed.

**Step 3: Verify build**

Run: `npx tsc --noEmit`
Expected: PASS

Run: `rm -rf dist && npx tsc --incremental false && npm run copy-yaml && npm run build-manifest`
Expected: 46 adapters, `enrichment/ip-enrich` (not `_enrichment/ip-enrich`)

**Step 4: Run tests**

Run: `npx vitest run --project unit`
Expected: All pass

**Step 5: Commit**

```bash
git add -A
git commit -m "refactor: rename _enrichment → enrichment directory"
```

---

## Task 6: Final verification

**Step 1: Clean build**

```bash
rm -rf dist && npx tsc --incremental false && npm run copy-yaml && npm run build-manifest
```

Expected: 46 adapters

**Step 2: Full test suite**

```bash
npx vitest run --project unit
```

Expected: All pass

**Step 3: Smoke test CLI**

```bash
node dist/main.js list --format json | node -e "const d=JSON.parse(require('fs').readFileSync('/dev/stdin','utf8')); console.log('Total:', d.length); const dups=d.map(e=>e.command).filter((c,i,a)=>a.indexOf(c)!==i); console.log('Duplicates:', dups.length ? dups : 'none')"
```

Expected: `Total: 46`, `Duplicates: none`

```bash
node dist/main.js crypto hash-id --hash 5d41402abc4b2a76b9719d911017c592 --format json
```

Expected: Valid JSON output

**Step 4: Commit**

```bash
git add -A
git commit -m "chore: verify clean build after P0 refactor"
```

---

## Summary of what gets deleted

| File | What's removed | Lines saved |
|------|---------------|-------------|
| `scan/analyze.ts` | `checkTool()`, `execFileAsync`, `runNpmAudit()`, `runPipAudit()`, `parseNpmAuditOutput()`, `parsePipAuditOutput()`, `normalizeNpmSeverity()` | ~140 |
| `scan/full.ts` | `toolExists()`, `execFileAsync`, inline semgrep/gitleaks IIFEs | ~50 |
| `pipeline/template.ts` | local `walkPath()` | ~10 |
| `pipeline/steps/enrich.ts` | local `walkPath()` | ~13 |
| `_enrichment/ip-enrich.ts` | local `walkPath()` | ~13 |
| `scan/entrypoints.ts` | local `walkDir()`, `SKIP_DIRS` | ~30 |
| `scan/discover.ts` | local `walkSourceFiles()`, `SKIP_DIRS` | ~30 |
| **Total removed** | | **~286 lines** |
| **Total added** (shared utils) | `walk-path.ts`, `fs-walk.ts`, tests | **~100 lines** |
| **Net reduction** | | **~186 lines** |

## Unresolved Questions

1. Should `scan/full` also call `supply-chain/dep-audit` to get dependency vulns in the full scan pipeline? Currently it only runs semgrep + gitleaks after this refactor. The dep-audit integration can be a follow-up task.
2. `scan/analyze.test.ts` has tests for `parseNpmAuditOutput` and `parsePipAuditOutput` — should they be migrated to `supply-chain.test.ts` or deleted? (The parsers are inline in `dep-audit.ts` and not exported, so these specific tests should just be deleted.)
