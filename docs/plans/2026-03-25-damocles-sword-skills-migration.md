# Damocles Sword Skills → OpenSecCLI CLI Migration Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Migrate damocles_sword 的 LLM security scanning skills 为 OpenSecCLI CLI 命令，保持当前仓库 Commander.js + TypeScript adapter 规范。

**Architecture:** 新建 `scan` provider，每个 skill 转为独立 TypeScript adapter（`cli()` 注册），通过 `child_process.execFile` 调用本地安全工具（semgrep、gitleaks 等），所有输出走 OpenSecCLI 标准 output pipeline（table/json/csv/yaml/markdown）。

**Tech Stack:** TypeScript, Commander.js, Node.js child_process, SARIF 2.1.0 format

---

## Skill 映射表

| damocles_sword Skill | OpenSecCLI Command | Phase | 依赖外部工具 |
|---|---|---|---|
| secscan-entrypoint-finder | `opensec scan entrypoints` | 1 | 无（纯正则） |
| secscan-discovery (git部分) | `opensec scan git-signals` | 1 | git |
| secscan-analysis | `opensec scan analyze` | 1 | semgrep, gitleaks, npm/pip audit |
| secscan-report | `opensec scan report` | 1 | 无 |
| secscan-discovery (完整) | `opensec scan discover` | 2 | git + Phase 1 |
| secscan-orchestrator | `opensec scan full` | 2 | Phase 1 全部 |
| secscan-semantic-hunter | `opensec scan semantic` | 3 (future) | Claude API |
| secscan-triage | `opensec scan triage` | 3 (future) | Claude API |

**本计划覆盖 Phase 1（4 个命令）+ Phase 2（2 个组合命令）。**

---

## Task 1: 共享类型定义 `src/adapters/scan/types.ts`

**Files:**
- Create: `src/adapters/scan/types.ts`
- Test: `tests/unit/scan-types.test.ts`

**Step 1: Write the test**

```typescript
// tests/unit/scan-types.test.ts
import { describe, it, expect } from 'vitest'
import type {
  EntryPoint, EntryPointKind, GitSignal,
  RawFinding, ScanReport, PhaseMetric,
} from '../../src/adapters/scan/types.js'

describe('scan types', () => {
  it('EntryPoint satisfies shape', () => {
    const ep: EntryPoint = {
      file: 'src/api.py',
      line: 42,
      kind: 'http_route',
      method: 'POST',
      pattern: '/api/users',
      framework: 'flask',
    }
    expect(ep.kind).toBe('http_route')
    expect(ep.file).toBe('src/api.py')
  })

  it('RawFinding satisfies shape', () => {
    const f: RawFinding = {
      rule_id: 'sql-injection',
      severity: 'high',
      message: 'SQL injection via string concat',
      file_path: 'src/search.py',
      start_line: 45,
      cwe: 'CWE-89',
      tools_used: ['semgrep'],
    }
    expect(f.cwe).toBe('CWE-89')
  })

  it('GitSignal satisfies shape', () => {
    const sig: GitSignal = {
      commit: 'abc1234',
      message: 'fix: sanitize input',
      files: ['src/search.py'],
      diff_summary: 'Added parameterized query',
    }
    expect(sig.files).toHaveLength(1)
  })
})
```

**Step 2: Run test → FAIL**

```bash
npx vitest run tests/unit/scan-types.test.ts
```
Expected: FAIL — module not found

**Step 3: Write the types**

```typescript
// src/adapters/scan/types.ts
export type EntryPointKind =
  | 'http_route'
  | 'rpc_handler'
  | 'websocket'
  | 'cli_command'
  | 'job_handler'
  | 'file_entry'

export interface EntryPoint {
  file: string
  line: number
  kind: EntryPointKind
  method?: string
  pattern?: string
  framework?: string
}

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'

export interface RawFinding {
  rule_id: string
  severity: Severity
  message: string
  file_path: string
  start_line: number
  cwe: string
  tools_used: string[]
  evidence_paths?: EvidencePath[]
  metadata?: Record<string, unknown>
}

export interface EvidencePath {
  source?: { file: string; line: number; label?: string }
  sink?: { file: string; line: number; label?: string }
  through?: Array<{ file: string; line: number; label?: string }>
}

export interface GitSignal {
  commit: string
  message: string
  files: string[]
  diff_summary?: string
  keywords?: string[]
}

export interface PhaseMetric {
  adapter: string
  latency_ms: number
  findings_count: number
  status: 'completed' | 'skipped' | 'failed' | 'timed_out'
  error?: string
}

export interface ProjectMap {
  path: string
  languages: string[]
  frameworks: string[]
  entry_points: EntryPoint[]
  git_security_signals: GitSignal[]
  source_files: string[]
  architecture_summary?: string
}

export interface ScanReport {
  target: string
  duration_ms: number
  summary: {
    total: number
    critical: number
    high: number
    medium: number
    low: number
  }
  findings: RawFinding[]
  phase_metrics: PhaseMetric[]
  tools_used: string[]
}
```

**Step 4: Run test → PASS**

```bash
npx vitest run tests/unit/scan-types.test.ts
```

**Step 5: Commit**

```bash
git add src/adapters/scan/types.ts tests/unit/scan-types.test.ts
git commit -m "feat(scan): add shared type definitions for scan provider"
```

---

## Task 2: Entry Point Finder `opensec scan entrypoints`

**Files:**
- Create: `src/adapters/scan/entrypoints.ts`
- Test: `tests/unit/scan-entrypoints.test.ts`

**来源:** `secscan-entrypoint-finder` — 纯正则匹配，无外部依赖

**Step 1: Write the test**

```typescript
// tests/unit/scan-entrypoints.test.ts
import { describe, it, expect } from 'vitest'
import { findEntryPoints, ROUTE_PATTERNS } from '../../src/adapters/scan/entrypoints.js'

describe('findEntryPoints', () => {
  it('detects Flask routes', () => {
    const code = `
from flask import Flask
app = Flask(__name__)

@app.route('/api/users', methods=['POST'])
def create_user():
    pass
`
    const eps = findEntryPoints('app.py', code, ['python'])
    expect(eps).toHaveLength(1)
    expect(eps[0]).toMatchObject({
      file: 'app.py',
      kind: 'http_route',
      pattern: '/api/users',
      framework: 'flask',
    })
    expect(eps[0].line).toBeGreaterThan(0)
  })

  it('detects FastAPI routes', () => {
    const code = `
from fastapi import FastAPI
app = FastAPI()

@app.get('/items/{item_id}')
async def read_item(item_id: int):
    return {"item_id": item_id}
`
    const eps = findEntryPoints('main.py', code, ['python'])
    expect(eps).toHaveLength(1)
    expect(eps[0]).toMatchObject({ kind: 'http_route', framework: 'fastapi' })
  })

  it('detects Express routes', () => {
    const code = `
const express = require('express')
const app = express()

app.get('/api/users', (req, res) => {
  res.json([])
})

router.post('/api/items', async (req, res) => {
  res.json({})
})
`
    const eps = findEntryPoints('server.js', code, ['javascript'])
    expect(eps).toHaveLength(2)
    expect(eps[0]).toMatchObject({ kind: 'http_route', framework: 'express' })
  })

  it('detects Django URL patterns', () => {
    const code = `
from django.urls import path
from . import views

urlpatterns = [
    path('api/users/', views.UserListView.as_view()),
    path('api/items/<int:pk>/', views.ItemDetailView.as_view()),
]
`
    const eps = findEntryPoints('urls.py', code, ['python'])
    expect(eps).toHaveLength(2)
    expect(eps[0]).toMatchObject({ kind: 'http_route', framework: 'django' })
  })

  it('detects Spring controllers', () => {
    const code = `
@RestController
@RequestMapping("/api")
public class UserController {

    @GetMapping("/users")
    public List<User> getUsers() {
        return userService.findAll();
    }

    @PostMapping("/users")
    public User createUser(@RequestBody UserDto dto) {
        return userService.create(dto);
    }
}
`
    const eps = findEntryPoints('UserController.java', code, ['java'])
    expect(eps).toHaveLength(2)
    expect(eps[0]).toMatchObject({ kind: 'http_route', framework: 'spring' })
  })

  it('returns empty for test files', () => {
    const code = `@app.route('/test')\ndef test_view(): pass`
    const eps = findEntryPoints('test_app.py', code, ['python'])
    expect(eps).toHaveLength(0)
  })

  it('returns empty for no matches', () => {
    const eps = findEntryPoints('utils.py', 'def add(a, b): return a + b', ['python'])
    expect(eps).toHaveLength(0)
  })
})
```

**Step 2: Run test → FAIL**

```bash
npx vitest run tests/unit/scan-entrypoints.test.ts
```

**Step 3: Implement**

```typescript
// src/adapters/scan/entrypoints.ts
import { cli, Strategy } from '../../registry.js'
import type { ExecContext } from '../../types.js'
import type { EntryPoint, EntryPointKind } from './types.js'
import { readdir, readFile, stat } from 'node:fs/promises'
import { join, extname, basename } from 'node:path'

interface RoutePattern {
  regex: RegExp
  kind: EntryPointKind
  framework: string
  languages: string[]
  extractRoute?: (match: RegExpMatchArray) => string | undefined
  extractMethod?: (match: RegExpMatchArray) => string | undefined
}

const TEST_FILE_PATTERNS = [
  /^test_/i, /_test\./i, /\.test\./i, /\.spec\./i,
  /^spec_/i, /\/tests?\//i, /\/__tests__\//i,
]

export const ROUTE_PATTERNS: RoutePattern[] = [
  // Flask / FastAPI
  {
    regex: /@\w+\.(route|get|post|put|delete|patch)\s*\(\s*['"]([^'"]+)['"]/gm,
    kind: 'http_route',
    framework: 'flask',
    languages: ['python'],
    extractRoute: (m) => m[2],
    extractMethod: (m) => m[1] === 'route' ? undefined : m[1]?.toUpperCase(),
  },
  // FastAPI-specific (with typing)
  {
    regex: /@\w+\.(get|post|put|delete|patch)\s*\(\s*['"]([^'"]+)['"]/gm,
    kind: 'http_route',
    framework: 'fastapi',
    languages: ['python'],
    extractRoute: (m) => m[2],
    extractMethod: (m) => m[1]?.toUpperCase(),
  },
  // Django urls.py
  {
    regex: /path\s*\(\s*['"]([^'"]+)['"]/gm,
    kind: 'http_route',
    framework: 'django',
    languages: ['python'],
    extractRoute: (m) => m[1],
  },
  // Express.js
  {
    regex: /(?:app|router)\.(get|post|put|delete|patch|all)\s*\(\s*['"]([^'"]+)['"]/gm,
    kind: 'http_route',
    framework: 'express',
    languages: ['javascript', 'typescript'],
    extractRoute: (m) => m[2],
    extractMethod: (m) => m[1]?.toUpperCase(),
  },
  // NestJS
  {
    regex: /@(Get|Post|Put|Delete|Patch)\s*\(\s*['"]([^'"]*)['"]\s*\)/gm,
    kind: 'http_route',
    framework: 'nestjs',
    languages: ['typescript'],
    extractRoute: (m) => m[2],
    extractMethod: (m) => m[1]?.toUpperCase(),
  },
  // Spring
  {
    regex: /@(GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping|RequestMapping)\s*\(\s*(?:value\s*=\s*)?['"]([^'"]+)['"]/gm,
    kind: 'http_route',
    framework: 'spring',
    languages: ['java'],
    extractRoute: (m) => m[2],
    extractMethod: (m) => {
      const map: Record<string, string> = {
        GetMapping: 'GET', PostMapping: 'POST', PutMapping: 'PUT',
        DeleteMapping: 'DELETE', PatchMapping: 'PATCH',
      }
      return map[m[1]] ?? undefined
    },
  },
  // Laravel
  {
    regex: /Route::(get|post|put|delete|patch|any)\s*\(\s*['"]([^'"]+)['"]/gm,
    kind: 'http_route',
    framework: 'laravel',
    languages: ['php'],
    extractRoute: (m) => m[2],
    extractMethod: (m) => m[1]?.toUpperCase(),
  },
]

function isTestFile(filePath: string): boolean {
  return TEST_FILE_PATTERNS.some(p => p.test(filePath))
}

function detectLanguages(filePath: string): string[] {
  const ext = extname(filePath).toLowerCase()
  const map: Record<string, string[]> = {
    '.py': ['python'],
    '.js': ['javascript'],
    '.ts': ['typescript'],
    '.tsx': ['typescript'],
    '.jsx': ['javascript'],
    '.java': ['java'],
    '.php': ['php'],
  }
  return map[ext] ?? []
}

export function findEntryPoints(
  filePath: string,
  content: string,
  languages: string[],
): EntryPoint[] {
  if (isTestFile(filePath)) return []

  const lines = content.split('\n')
  const results: EntryPoint[] = []
  const seen = new Set<string>()

  for (const pattern of ROUTE_PATTERNS) {
    if (!pattern.languages.some(l => languages.includes(l))) continue

    const regex = new RegExp(pattern.regex.source, pattern.regex.flags)
    let match: RegExpExecArray | null

    while ((match = regex.exec(content)) !== null) {
      const lineNum = content.slice(0, match.index).split('\n').length
      const route = pattern.extractRoute?.(match)
      const method = pattern.extractMethod?.(match)
      const key = `${filePath}:${lineNum}`

      if (seen.has(key)) continue
      seen.add(key)

      results.push({
        file: filePath,
        line: lineNum,
        kind: pattern.kind,
        ...(method && { method }),
        ...(route && { pattern: route }),
        framework: pattern.framework,
      })
    }
  }

  return results
}

const SCAN_EXTENSIONS = new Set([
  '.py', '.js', '.ts', '.tsx', '.jsx', '.java', '.php',
])

const SKIP_DIRS = new Set([
  'node_modules', '.git', '__pycache__', '.venv', 'venv',
  'dist', 'build', '.next', 'vendor', 'target',
])

async function walkDir(dir: string, maxDepth = 10): Promise<string[]> {
  if (maxDepth <= 0) return []
  const files: string[] = []

  try {
    const entries = await readdir(dir, { withFileTypes: true })
    for (const entry of entries) {
      if (entry.name.startsWith('.') && entry.name !== '.') continue
      if (SKIP_DIRS.has(entry.name)) continue

      const fullPath = join(dir, entry.name)
      if (entry.isDirectory()) {
        const sub = await walkDir(fullPath, maxDepth - 1)
        files.push(...sub)
      } else if (SCAN_EXTENSIONS.has(extname(entry.name).toLowerCase())) {
        files.push(fullPath)
      }
    }
  } catch {
    // Permission denied or other fs error — skip
  }

  return files
}

cli({
  provider: 'scan',
  name: 'entrypoints',
  description: 'Find HTTP routes, RPC handlers, and other entry points in a codebase',
  strategy: Strategy.FREE,
  args: {
    path: { type: 'string', required: true, help: 'Path to project root' },
    language: { type: 'string', required: false, help: 'Filter by language (python/javascript/typescript/java/php)' },
  },
  columns: ['file', 'line', 'kind', 'method', 'pattern', 'framework'],

  async func(ctx: ExecContext, args: Record<string, unknown>): Promise<unknown> {
    const targetPath = args.path as string
    const langFilter = args.language as string | undefined

    ctx.log.info(`Scanning ${targetPath} for entry points...`)

    const files = await walkDir(targetPath)
    ctx.log.verbose(`Found ${files.length} source files`)

    const allEntryPoints: EntryPoint[] = []

    for (const file of files) {
      try {
        const content = await readFile(file, 'utf-8')
        const relativePath = file.replace(targetPath + '/', '')
        const langs = langFilter ? [langFilter] : detectLanguages(file)
        const eps = findEntryPoints(relativePath, content, langs)
        allEntryPoints.push(...eps)
      } catch {
        ctx.log.debug(`Skipped unreadable file: ${file}`)
      }
    }

    if (allEntryPoints.length === 0) {
      ctx.log.warn('No entry points detected. Check language support.')
      return []
    }

    ctx.log.info(`Found ${allEntryPoints.length} entry points`)
    return allEntryPoints
  },
})
```

**Step 4: Run test → PASS**

```bash
npx vitest run tests/unit/scan-entrypoints.test.ts
```

**Step 5: Commit**

```bash
git add src/adapters/scan/entrypoints.ts tests/unit/scan-entrypoints.test.ts
git commit -m "feat(scan): add entrypoint finder for multi-language route discovery"
```

---

## Task 3: Git Security Signals `opensec scan git-signals`

**Files:**
- Create: `src/adapters/scan/git-signals.ts`
- Test: `tests/unit/scan-git-signals.test.ts`

**来源:** `secscan-discovery` git history 部分 + `secscan-missed-patch-hunter` 信号提取

**Step 1: Write the test**

```typescript
// tests/unit/scan-git-signals.test.ts
import { describe, it, expect } from 'vitest'
import { extractSignals, SECURITY_KEYWORDS } from '../../src/adapters/scan/git-signals.js'

describe('extractSignals', () => {
  it('matches security-relevant commit messages', () => {
    const logs = [
      { hash: 'aaa', message: 'fix: prevent SQL injection in search', files: ['src/search.py'] },
      { hash: 'bbb', message: 'feat: add user profile page', files: ['src/profile.py'] },
      { hash: 'ccc', message: 'fix: escape XSS in template rendering', files: ['src/render.py'] },
      { hash: 'ddd', message: 'chore: update deps', files: ['package.json'] },
    ]
    const signals = extractSignals(logs)
    expect(signals).toHaveLength(2)
    expect(signals[0].commit).toBe('aaa')
    expect(signals[1].commit).toBe('ccc')
  })

  it('extracts matched keywords', () => {
    const logs = [
      { hash: 'aaa', message: 'fix: sanitize input to prevent injection', files: ['src/input.py'] },
    ]
    const signals = extractSignals(logs)
    expect(signals[0].keywords).toContain('sanitize')
    expect(signals[0].keywords).toContain('inject')
  })

  it('respects max signals limit', () => {
    const logs = Array.from({ length: 30 }, (_, i) => ({
      hash: `h${i}`,
      message: `fix: vulnerability CVE-${i}`,
      files: [`src/file${i}.py`],
    }))
    const signals = extractSignals(logs, 20)
    expect(signals).toHaveLength(20)
  })

  it('returns empty for no security commits', () => {
    const logs = [
      { hash: 'aaa', message: 'feat: add pagination', files: ['src/list.py'] },
    ]
    expect(extractSignals(logs)).toHaveLength(0)
  })
})

describe('SECURITY_KEYWORDS', () => {
  it('includes core keywords', () => {
    expect(SECURITY_KEYWORDS).toContain('vuln')
    expect(SECURITY_KEYWORDS).toContain('xss')
    expect(SECURITY_KEYWORDS).toContain('inject')
    expect(SECURITY_KEYWORDS).toContain('cve')
  })
})
```

**Step 2: Run test → FAIL**

```bash
npx vitest run tests/unit/scan-git-signals.test.ts
```

**Step 3: Implement**

```typescript
// src/adapters/scan/git-signals.ts
import { cli, Strategy } from '../../registry.js'
import type { ExecContext } from '../../types.js'
import type { GitSignal } from './types.js'
import { execFile } from 'node:child_process'
import { promisify } from 'node:util'

const execFileAsync = promisify(execFile)

export const SECURITY_KEYWORDS = [
  'fix', 'vuln', 'cve', 'xss', 'sqli', 'rce',
  'auth', 'sanitize', 'escape', 'inject', 'overflow',
  'bypass', 'csrf', 'ssrf', 'idor', 'traversal',
  'deserialization', 'credential', 'secret', 'token',
  'permission', 'privilege', 'security',
]

const KEYWORD_REGEX = new RegExp(
  `\\b(${SECURITY_KEYWORDS.join('|')})`,
  'gi',
)

interface CommitLog {
  hash: string
  message: string
  files: string[]
}

export function extractSignals(
  logs: CommitLog[],
  maxSignals = 20,
): GitSignal[] {
  const signals: GitSignal[] = []

  for (const log of logs) {
    if (signals.length >= maxSignals) break

    const matches = log.message.toLowerCase().match(KEYWORD_REGEX)
    if (!matches || matches.length === 0) continue

    const keywords = [...new Set(matches.map(m => m.toLowerCase()))]

    signals.push({
      commit: log.hash,
      message: log.message,
      files: log.files,
      keywords,
    })
  }

  return signals
}

async function getGitLog(
  repoPath: string,
  maxCommits: number,
): Promise<CommitLog[]> {
  const { stdout } = await execFileAsync(
    'git',
    ['log', `--max-count=${maxCommits}`, '--format=%H%x00%s', '--name-only'],
    { cwd: repoPath, maxBuffer: 10 * 1024 * 1024 },
  )

  const commits: CommitLog[] = []
  const blocks = stdout.trim().split('\n\n')

  for (const block of blocks) {
    const lines = block.split('\n').filter(Boolean)
    if (lines.length === 0) continue

    const [headerLine, ...fileLines] = lines
    const sepIdx = headerLine.indexOf('\0')
    if (sepIdx === -1) continue

    const hash = headerLine.slice(0, sepIdx)
    const message = headerLine.slice(sepIdx + 1)
    const files = fileLines.filter(f => f.trim().length > 0)

    commits.push({ hash, message, files })
  }

  return commits
}

cli({
  provider: 'scan',
  name: 'git-signals',
  description: 'Extract security-relevant commits from git history',
  strategy: Strategy.FREE,
  args: {
    path: { type: 'string', required: true, help: 'Path to git repository' },
    max_commits: { type: 'number', required: false, default: 80, help: 'Max commits to scan (default: 80)' },
    max_signals: { type: 'number', required: false, default: 20, help: 'Max signals to return (default: 20)' },
  },
  columns: ['commit', 'message', 'files', 'keywords'],

  async func(ctx: ExecContext, args: Record<string, unknown>): Promise<unknown> {
    const repoPath = args.path as string
    const maxCommits = (args.max_commits as number) ?? 80
    const maxSignals = (args.max_signals as number) ?? 20

    ctx.log.info(`Scanning git history in ${repoPath} (last ${maxCommits} commits)...`)

    try {
      const logs = await getGitLog(repoPath, maxCommits)
      ctx.log.verbose(`Parsed ${logs.length} commits`)

      const signals = extractSignals(logs, maxSignals)

      if (signals.length === 0) {
        ctx.log.warn('No security-relevant commits found')
        return []
      }

      ctx.log.info(`Found ${signals.length} security signals`)

      return signals.map(s => ({
        ...s,
        files: s.files.join(', '),
        keywords: s.keywords?.join(', ') ?? '',
      }))
    } catch (error) {
      throw new Error(`Git scan failed: ${(error as Error).message}`)
    }
  },
})
```

**Step 4: Run test → PASS**

```bash
npx vitest run tests/unit/scan-git-signals.test.ts
```

**Step 5: Commit**

```bash
git add src/adapters/scan/git-signals.ts tests/unit/scan-git-signals.test.ts
git commit -m "feat(scan): add git security signal extraction from commit history"
```

---

## Task 4: Static Analysis Runner `opensec scan analyze`

**Files:**
- Create: `src/adapters/scan/analyze.ts`
- Test: `tests/unit/scan-analyze.test.ts`

**来源:** `secscan-analysis` — 协调多个静态分析工具

**Step 1: Write the test**

```typescript
// tests/unit/scan-analyze.test.ts
import { describe, it, expect, vi, beforeEach } from 'vitest'
import {
  parseSemgrepOutput,
  parseGitleaksOutput,
  parseNpmAuditOutput,
  parsePipAuditOutput,
  normalizeFindings,
  deduplicateFindings,
} from '../../src/adapters/scan/analyze.js'

describe('parseSemgrepOutput', () => {
  it('parses semgrep JSON results', () => {
    const output = {
      results: [
        {
          check_id: 'python.lang.security.audit.dangerous-system-call',
          path: 'src/cmd.py',
          start: { line: 12 },
          extra: {
            message: 'Detected dangerous system call',
            severity: 'ERROR',
            metadata: { cwe: ['CWE-78: OS Command Injection'] },
          },
        },
      ],
    }
    const findings = parseSemgrepOutput(output)
    expect(findings).toHaveLength(1)
    expect(findings[0]).toMatchObject({
      rule_id: 'python.lang.security.audit.dangerous-system-call',
      file_path: 'src/cmd.py',
      start_line: 12,
      severity: 'high',
      cwe: 'CWE-78',
      tools_used: ['semgrep'],
    })
  })
})

describe('parseGitleaksOutput', () => {
  it('parses gitleaks JSON results', () => {
    const output = [
      {
        RuleID: 'generic-api-key',
        File: 'config.py',
        StartLine: 5,
        Description: 'Generic API Key',
      },
    ]
    const findings = parseGitleaksOutput(output)
    expect(findings).toHaveLength(1)
    expect(findings[0]).toMatchObject({
      rule_id: 'generic-api-key',
      cwe: 'CWE-798',
      tools_used: ['gitleaks'],
    })
  })
})

describe('deduplicateFindings', () => {
  it('merges findings with same file:line:cwe', () => {
    const findings = [
      { rule_id: 'sqli-1', severity: 'high' as const, message: 'SQL injection', file_path: 'a.py', start_line: 10, cwe: 'CWE-89', tools_used: ['semgrep'] },
      { rule_id: 'sqli-2', severity: 'high' as const, message: 'SQL injection variant', file_path: 'a.py', start_line: 10, cwe: 'CWE-89', tools_used: ['semantic'] },
    ]
    const deduped = deduplicateFindings(findings)
    expect(deduped).toHaveLength(1)
    expect(deduped[0].tools_used).toContain('semgrep')
    expect(deduped[0].tools_used).toContain('semantic')
  })

  it('keeps findings with different keys', () => {
    const findings = [
      { rule_id: 'sqli', severity: 'high' as const, message: 'SQL injection', file_path: 'a.py', start_line: 10, cwe: 'CWE-89', tools_used: ['semgrep'] },
      { rule_id: 'xss', severity: 'medium' as const, message: 'XSS', file_path: 'b.py', start_line: 20, cwe: 'CWE-79', tools_used: ['semgrep'] },
    ]
    const deduped = deduplicateFindings(findings)
    expect(deduped).toHaveLength(2)
  })
})
```

**Step 2: Run test → FAIL**

```bash
npx vitest run tests/unit/scan-analyze.test.ts
```

**Step 3: Implement**

```typescript
// src/adapters/scan/analyze.ts
import { cli, Strategy } from '../../registry.js'
import type { ExecContext } from '../../types.js'
import type { RawFinding, Severity, PhaseMetric } from './types.js'
import { execFile } from 'node:child_process'
import { promisify } from 'node:util'

const execFileAsync = promisify(execFile)

// --- Parsers ---

const SEMGREP_SEVERITY_MAP: Record<string, Severity> = {
  ERROR: 'high',
  WARNING: 'medium',
  INFO: 'low',
}

export function parseSemgrepOutput(output: { results: Array<Record<string, unknown>> }): RawFinding[] {
  return (output.results ?? []).map((r: Record<string, unknown>) => {
    const extra = r.extra as Record<string, unknown> ?? {}
    const metadata = extra.metadata as Record<string, unknown> ?? {}
    const cweList = metadata.cwe as string[] ?? []
    const rawCwe = cweList[0] ?? ''
    const cwe = rawCwe.match(/CWE-\d+/)?.[0] ?? ''

    return {
      rule_id: r.check_id as string,
      severity: SEMGREP_SEVERITY_MAP[extra.severity as string] ?? 'medium',
      message: extra.message as string ?? '',
      file_path: r.path as string,
      start_line: (r.start as Record<string, number>)?.line ?? 0,
      cwe,
      tools_used: ['semgrep'],
    }
  })
}

export function parseGitleaksOutput(output: Array<Record<string, unknown>>): RawFinding[] {
  return output.map(r => ({
    rule_id: r.RuleID as string,
    severity: 'high' as Severity,
    message: (r.Description as string) ?? 'Hardcoded secret detected',
    file_path: r.File as string,
    start_line: (r.StartLine as number) ?? 0,
    cwe: 'CWE-798',
    tools_used: ['gitleaks'],
  }))
}

export function parseNpmAuditOutput(output: Record<string, unknown>): RawFinding[] {
  const vulnerabilities = output.vulnerabilities as Record<string, Record<string, unknown>> ?? {}
  return Object.values(vulnerabilities).map(v => ({
    rule_id: `npm-${v.name as string}`,
    severity: normalizeNpmSeverity(v.severity as string),
    message: `${v.name}: ${v.title ?? v.via ?? 'vulnerable dependency'}`,
    file_path: 'package.json',
    start_line: 0,
    cwe: '',
    tools_used: ['npm-audit'],
  }))
}

export function parsePipAuditOutput(output: Array<Record<string, unknown>>): RawFinding[] {
  return output.map(v => ({
    rule_id: `pip-${v.name as string}-${v.id ?? ''}`,
    severity: 'medium' as Severity,
    message: `${v.name} ${v.version}: ${v.description ?? 'known vulnerability'}`,
    file_path: 'requirements.txt',
    start_line: 0,
    cwe: '',
    tools_used: ['pip-audit'],
  }))
}

function normalizeNpmSeverity(s: string): Severity {
  const map: Record<string, Severity> = {
    critical: 'critical', high: 'high', moderate: 'medium', low: 'low', info: 'info',
  }
  return map[s] ?? 'medium'
}

// --- Normalize & Dedup ---

export function normalizeFindings(findings: RawFinding[]): RawFinding[] {
  return findings.map(f => ({
    ...f,
    severity: f.severity ?? 'medium',
    cwe: f.cwe ?? '',
    tools_used: f.tools_used ?? [],
  }))
}

export function deduplicateFindings(findings: RawFinding[]): RawFinding[] {
  const map = new Map<string, RawFinding>()

  for (const f of findings) {
    const key = `${f.file_path}:${f.start_line}:${f.cwe || f.rule_id}`
    const existing = map.get(key)

    if (existing) {
      map.set(key, {
        ...existing,
        tools_used: [...new Set([...existing.tools_used, ...f.tools_used])],
      })
    } else {
      map.set(key, { ...f })
    }
  }

  return [...map.values()]
}

// --- Tool Runners ---

async function checkTool(name: string): Promise<boolean> {
  try {
    await execFileAsync('which', [name])
    return true
  } catch {
    return false
  }
}

async function runSemgrep(
  repoPath: string,
  ctx: ExecContext,
): Promise<{ findings: RawFinding[]; metric: PhaseMetric }> {
  const start = Date.now()
  try {
    const { stdout } = await execFileAsync(
      'semgrep',
      ['scan', '--json', '--config', 'auto', repoPath],
      { maxBuffer: 50 * 1024 * 1024, timeout: 120_000 },
    )
    const output = JSON.parse(stdout)
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

async function runGitleaks(
  repoPath: string,
  ctx: ExecContext,
): Promise<{ findings: RawFinding[]; metric: PhaseMetric }> {
  const start = Date.now()
  try {
    const { stdout } = await execFileAsync(
      'gitleaks',
      ['detect', '--source', repoPath, '--report-format', 'json', '--report-path', '/dev/stdout', '--no-banner'],
      { maxBuffer: 10 * 1024 * 1024, timeout: 60_000 },
    )
    const output = JSON.parse(stdout || '[]')
    const findings = parseGitleaksOutput(output)
    return {
      findings,
      metric: { adapter: 'gitleaks', latency_ms: Date.now() - start, findings_count: findings.length, status: 'completed' },
    }
  } catch (error) {
    const msg = (error as Error).message
    // gitleaks exits with 1 when leaks are found
    if (msg.includes('exit code 1')) {
      return {
        findings: [],
        metric: { adapter: 'gitleaks', latency_ms: Date.now() - start, findings_count: 0, status: 'completed' },
      }
    }
    ctx.log.warn(`Gitleaks failed: ${msg}`)
    return {
      findings: [],
      metric: { adapter: 'gitleaks', latency_ms: Date.now() - start, findings_count: 0, status: 'failed', error: msg },
    }
  }
}

async function runNpmAudit(
  repoPath: string,
  ctx: ExecContext,
): Promise<{ findings: RawFinding[]; metric: PhaseMetric }> {
  const start = Date.now()
  try {
    const { stdout } = await execFileAsync(
      'npm',
      ['audit', '--json'],
      { cwd: repoPath, maxBuffer: 10 * 1024 * 1024, timeout: 60_000 },
    )
    const output = JSON.parse(stdout)
    const findings = parseNpmAuditOutput(output)
    return {
      findings,
      metric: { adapter: 'npm-audit', latency_ms: Date.now() - start, findings_count: findings.length, status: 'completed' },
    }
  } catch (error) {
    // npm audit exits non-zero when vulns found — try to parse stdout from error
    const errWithOutput = error as { stdout?: string; message: string }
    if (errWithOutput.stdout) {
      try {
        const output = JSON.parse(errWithOutput.stdout)
        const findings = parseNpmAuditOutput(output)
        return {
          findings,
          metric: { adapter: 'npm-audit', latency_ms: Date.now() - start, findings_count: findings.length, status: 'completed' },
        }
      } catch { /* fall through */ }
    }
    ctx.log.warn(`npm audit failed: ${(error as Error).message}`)
    return {
      findings: [],
      metric: { adapter: 'npm-audit', latency_ms: Date.now() - start, findings_count: 0, status: 'failed', error: (error as Error).message },
    }
  }
}

async function runPipAudit(
  repoPath: string,
  ctx: ExecContext,
): Promise<{ findings: RawFinding[]; metric: PhaseMetric }> {
  const start = Date.now()
  try {
    const { stdout } = await execFileAsync(
      'pip-audit',
      ['--format', 'json', '-r', `${repoPath}/requirements.txt`],
      { maxBuffer: 10 * 1024 * 1024, timeout: 60_000 },
    )
    const output = JSON.parse(stdout)
    const findings = parsePipAuditOutput(output)
    return {
      findings,
      metric: { adapter: 'pip-audit', latency_ms: Date.now() - start, findings_count: findings.length, status: 'completed' },
    }
  } catch (error) {
    ctx.log.warn(`pip-audit failed: ${(error as Error).message}`)
    return {
      findings: [],
      metric: { adapter: 'pip-audit', latency_ms: Date.now() - start, findings_count: 0, status: 'failed', error: (error as Error).message },
    }
  }
}

// --- CLI Registration ---

cli({
  provider: 'scan',
  name: 'analyze',
  description: 'Run static security analysis (semgrep, gitleaks, npm/pip audit) on a codebase',
  strategy: Strategy.FREE,
  args: {
    path: { type: 'string', required: true, help: 'Path to project root' },
    tools: { type: 'string', required: false, default: 'auto', help: 'Comma-separated tools: semgrep,gitleaks,npm-audit,pip-audit (default: auto-detect)' },
  },
  columns: ['rule_id', 'severity', 'file_path', 'start_line', 'cwe', 'message', 'tools_used'],
  timeout: 300,

  async func(ctx: ExecContext, args: Record<string, unknown>): Promise<unknown> {
    const repoPath = args.path as string
    const toolsArg = (args.tools as string) ?? 'auto'

    // Detect available tools
    const available: Record<string, boolean> = {}
    const toolNames = ['semgrep', 'gitleaks', 'npm', 'pip-audit']

    await Promise.all(
      toolNames.map(async t => {
        available[t] = await checkTool(t)
      }),
    )

    const requestedTools = toolsArg === 'auto'
      ? toolNames.filter(t => available[t])
      : toolsArg.split(',').map(t => t.trim())

    ctx.log.info(`Running analysis with: ${requestedTools.join(', ')}`)

    // Run all available tools in parallel
    const runners: Array<Promise<{ findings: RawFinding[]; metric: PhaseMetric }>> = []

    if (requestedTools.includes('semgrep') && available.semgrep) {
      runners.push(runSemgrep(repoPath, ctx))
    }
    if (requestedTools.includes('gitleaks') && available.gitleaks) {
      runners.push(runGitleaks(repoPath, ctx))
    }
    if (requestedTools.includes('npm-audit') && available.npm) {
      runners.push(runNpmAudit(repoPath, ctx))
    }
    if (requestedTools.includes('pip-audit') && available['pip-audit']) {
      runners.push(runPipAudit(repoPath, ctx))
    }

    if (runners.length === 0) {
      ctx.log.warn('No analysis tools available. Install semgrep, gitleaks, or use npm/pip-audit.')
      return []
    }

    const results = await Promise.allSettled(runners)

    const allFindings: RawFinding[] = []
    const metrics: PhaseMetric[] = []

    for (const result of results) {
      if (result.status === 'fulfilled') {
        allFindings.push(...result.value.findings)
        metrics.push(result.value.metric)
      }
    }

    const normalized = normalizeFindings(allFindings)
    const deduped = deduplicateFindings(normalized)

    ctx.log.info(`Analysis complete: ${deduped.length} findings (${metrics.filter(m => m.status === 'completed').length}/${metrics.length} tools succeeded)`)

    for (const m of metrics) {
      ctx.log.verbose(`  ${m.adapter}: ${m.status} (${m.latency_ms}ms, ${m.findings_count} findings)`)
    }

    return deduped.map(f => ({
      ...f,
      tools_used: f.tools_used.join(', '),
    }))
  },
})
```

**Step 4: Run test → PASS**

```bash
npx vitest run tests/unit/scan-analyze.test.ts
```

**Step 5: Commit**

```bash
git add src/adapters/scan/analyze.ts tests/unit/scan-analyze.test.ts
git commit -m "feat(scan): add multi-tool static analysis runner"
```

---

## Task 5: Report Generator `opensec scan report`

**Files:**
- Create: `src/adapters/scan/report.ts`
- Test: `tests/unit/scan-report.test.ts`

**来源:** `secscan-report` — JSON / SARIF / Markdown 输出

**Step 1: Write the test**

```typescript
// tests/unit/scan-report.test.ts
import { describe, it, expect } from 'vitest'
import {
  buildJsonReport,
  buildSarifReport,
  buildMarkdownReport,
  severityToSarif,
} from '../../src/adapters/scan/report.js'
import type { RawFinding } from '../../src/adapters/scan/types.js'

const SAMPLE_FINDINGS: RawFinding[] = [
  {
    rule_id: 'sql-injection',
    severity: 'high',
    message: 'SQL injection via string concat',
    file_path: 'src/search.py',
    start_line: 45,
    cwe: 'CWE-89',
    tools_used: ['semgrep'],
  },
  {
    rule_id: 'hardcoded-secret',
    severity: 'critical',
    message: 'API key in source',
    file_path: 'config.py',
    start_line: 10,
    cwe: 'CWE-798',
    tools_used: ['gitleaks'],
  },
]

describe('buildJsonReport', () => {
  it('produces valid JSON report structure', () => {
    const report = buildJsonReport(SAMPLE_FINDINGS, '/repo', 5000)
    expect(report.target).toBe('/repo')
    expect(report.duration_ms).toBe(5000)
    expect(report.findings).toHaveLength(2)
    expect(report.summary.total).toBe(2)
    expect(report.summary.critical).toBe(1)
    expect(report.summary.high).toBe(1)
  })
})

describe('buildSarifReport', () => {
  it('produces valid SARIF 2.1.0 structure', () => {
    const sarif = buildSarifReport(SAMPLE_FINDINGS)
    expect(sarif.$schema).toContain('sarif')
    expect(sarif.version).toBe('2.1.0')
    expect(sarif.runs).toHaveLength(1)
    expect(sarif.runs[0].results).toHaveLength(2)
    expect(sarif.runs[0].tool.driver.name).toBe('OpenSecCLI')
  })

  it('maps severity correctly', () => {
    expect(severityToSarif('critical')).toBe('error')
    expect(severityToSarif('high')).toBe('error')
    expect(severityToSarif('medium')).toBe('warning')
    expect(severityToSarif('low')).toBe('note')
    expect(severityToSarif('info')).toBe('note')
  })
})

describe('buildMarkdownReport', () => {
  it('produces markdown with severity sections', () => {
    const md = buildMarkdownReport(SAMPLE_FINDINGS, '/repo', 5000)
    expect(md).toContain('# Security Scan Report')
    expect(md).toContain('CWE-89')
    expect(md).toContain('CWE-798')
    expect(md).toContain('Critical')
    expect(md).toContain('High')
    expect(md).toContain('2 findings')
  })

  it('handles empty findings', () => {
    const md = buildMarkdownReport([], '/repo', 1000)
    expect(md).toContain('No security findings')
  })
})
```

**Step 2: Run test → FAIL**

```bash
npx vitest run tests/unit/scan-report.test.ts
```

**Step 3: Implement**

```typescript
// src/adapters/scan/report.ts
import { cli, Strategy } from '../../registry.js'
import type { ExecContext } from '../../types.js'
import type { RawFinding, Severity, ScanReport } from './types.js'
import { readFile, writeFile, mkdir } from 'node:fs/promises'
import { join } from 'node:path'

// --- Report Builders ---

export function buildJsonReport(
  findings: RawFinding[],
  target: string,
  durationMs: number,
): ScanReport {
  const summary = {
    total: findings.length,
    critical: findings.filter(f => f.severity === 'critical').length,
    high: findings.filter(f => f.severity === 'high').length,
    medium: findings.filter(f => f.severity === 'medium').length,
    low: findings.filter(f => f.severity === 'low').length,
  }

  const toolsUsed = [...new Set(findings.flatMap(f => f.tools_used))]

  return {
    target,
    duration_ms: durationMs,
    summary,
    findings,
    phase_metrics: [],
    tools_used: toolsUsed,
  }
}

export function severityToSarif(severity: Severity): string {
  const map: Record<Severity, string> = {
    critical: 'error',
    high: 'error',
    medium: 'warning',
    low: 'note',
    info: 'note',
  }
  return map[severity] ?? 'warning'
}

export function buildSarifReport(findings: RawFinding[]): Record<string, unknown> {
  const rules = findings.map((f, i) => ({
    id: f.rule_id,
    shortDescription: { text: f.message },
    properties: {
      ...(f.cwe && { cwe: f.cwe }),
      severity: f.severity,
    },
  }))

  const uniqueRules = [...new Map(rules.map(r => [r.id, r])).values()]

  const results = findings.map(f => ({
    ruleId: f.rule_id,
    level: severityToSarif(f.severity),
    message: { text: f.message },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri: f.file_path },
          region: { startLine: f.start_line },
        },
      },
    ],
    properties: {
      cwe: f.cwe,
      tools_used: f.tools_used,
    },
  }))

  return {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'OpenSecCLI',
            version: '0.1.0',
            rules: uniqueRules,
          },
        },
        results,
      },
    ],
  }
}

const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info']

export function buildMarkdownReport(
  findings: RawFinding[],
  target: string,
  durationMs: number,
): string {
  const lines: string[] = [
    '# Security Scan Report',
    '',
    `**Target:** \`${target}\``,
    `**Duration:** ${(durationMs / 1000).toFixed(1)}s`,
    `**Total:** ${findings.length} findings`,
    '',
  ]

  if (findings.length === 0) {
    lines.push('No security findings detected.')
    return lines.join('\n')
  }

  for (const severity of SEVERITY_ORDER) {
    const group = findings.filter(f => f.severity === severity)
    if (group.length === 0) continue

    const label = severity.charAt(0).toUpperCase() + severity.slice(1)
    lines.push(`## ${label} (${group.length})`, '')

    for (const f of group) {
      lines.push(`### ${f.rule_id}`)
      lines.push(`- **File:** \`${f.file_path}:${f.start_line}\``)
      if (f.cwe) lines.push(`- **CWE:** ${f.cwe}`)
      lines.push(`- **Tools:** ${f.tools_used.join(', ')}`)
      lines.push(`- ${f.message}`)
      lines.push('')
    }
  }

  return lines.join('\n')
}

// --- CLI Registration ---

cli({
  provider: 'scan',
  name: 'report',
  description: 'Generate security scan reports (JSON, SARIF, Markdown) from findings',
  strategy: Strategy.FREE,
  args: {
    input: { type: 'string', required: true, help: 'Path to findings JSON file (output of `scan analyze --format json`)' },
    output_dir: { type: 'string', required: false, default: './scan-results', help: 'Output directory for reports' },
    formats: { type: 'string', required: false, default: 'json,sarif,markdown', help: 'Comma-separated output formats' },
  },
  columns: ['format', 'file', 'status'],

  async func(ctx: ExecContext, args: Record<string, unknown>): Promise<unknown> {
    const inputPath = args.input as string
    const outputDir = (args.output_dir as string) ?? './scan-results'
    const formats = ((args.formats as string) ?? 'json,sarif,markdown').split(',').map(f => f.trim())

    ctx.log.info(`Reading findings from ${inputPath}...`)

    const raw = await readFile(inputPath, 'utf-8')
    const findings: RawFinding[] = JSON.parse(raw)

    if (!Array.isArray(findings)) {
      throw new Error('Input must be a JSON array of findings')
    }

    await mkdir(outputDir, { recursive: true })

    const results: Array<{ format: string; file: string; status: string }> = []

    if (formats.includes('json')) {
      const report = buildJsonReport(findings, inputPath, 0)
      const outPath = join(outputDir, 'results.json')
      await writeFile(outPath, JSON.stringify(report, null, 2))
      results.push({ format: 'JSON', file: outPath, status: 'ok' })
      ctx.log.info(`Written: ${outPath}`)
    }

    if (formats.includes('sarif')) {
      const sarif = buildSarifReport(findings)
      const outPath = join(outputDir, 'results.sarif')
      await writeFile(outPath, JSON.stringify(sarif, null, 2))
      results.push({ format: 'SARIF', file: outPath, status: 'ok' })
      ctx.log.info(`Written: ${outPath}`)
    }

    if (formats.includes('markdown')) {
      const md = buildMarkdownReport(findings, inputPath, 0)
      const outPath = join(outputDir, 'results.md')
      await writeFile(outPath, md)
      results.push({ format: 'Markdown', file: outPath, status: 'ok' })
      ctx.log.info(`Written: ${outPath}`)
    }

    return results
  },
})
```

**Step 4: Run test → PASS**

```bash
npx vitest run tests/unit/scan-report.test.ts
```

**Step 5: Commit**

```bash
git add src/adapters/scan/report.ts tests/unit/scan-report.test.ts
git commit -m "feat(scan): add report generator with JSON, SARIF, and Markdown output"
```

---

## Task 6: Project Discovery `opensec scan discover`

**Files:**
- Create: `src/adapters/scan/discover.ts`
- Test: `tests/unit/scan-discover.test.ts`

**来源:** `secscan-discovery` — 组合 entrypoints + git-signals + 语言/框架检测

**Step 1: Write the test**

```typescript
// tests/unit/scan-discover.test.ts
import { describe, it, expect } from 'vitest'
import {
  detectLanguages,
  detectFrameworks,
  buildProjectMap,
} from '../../src/adapters/scan/discover.js'

describe('detectLanguages', () => {
  it('detects from file extensions', () => {
    const files = ['src/app.py', 'src/utils.py', 'lib/helper.js', 'README.md']
    const langs = detectLanguages(files)
    expect(langs).toContain('python')
    expect(langs).toContain('javascript')
    expect(langs).not.toContain('markdown')
  })
})

describe('detectFrameworks', () => {
  it('detects Flask from imports', () => {
    const contents = new Map([
      ['app.py', 'from flask import Flask\napp = Flask(__name__)'],
    ])
    const frameworks = detectFrameworks(contents)
    expect(frameworks).toContain('flask')
  })

  it('detects Express from require', () => {
    const contents = new Map([
      ['server.js', "const express = require('express')\nconst app = express()"],
    ])
    const frameworks = detectFrameworks(contents)
    expect(frameworks).toContain('express')
  })

  it('detects multiple frameworks', () => {
    const contents = new Map([
      ['app.py', 'from fastapi import FastAPI'],
      ['server.js', "import express from 'express'"],
    ])
    const frameworks = detectFrameworks(contents)
    expect(frameworks).toContain('fastapi')
    expect(frameworks).toContain('express')
  })
})

describe('buildProjectMap', () => {
  it('assembles all discovery data', () => {
    const map = buildProjectMap({
      path: '/repo',
      languages: ['python'],
      frameworks: ['flask'],
      entryPoints: [{ file: 'app.py', line: 10, kind: 'http_route' as const }],
      gitSignals: [{ commit: 'abc', message: 'fix: xss', files: ['a.py'] }],
      sourceFiles: ['app.py', 'utils.py'],
    })
    expect(map.path).toBe('/repo')
    expect(map.languages).toEqual(['python'])
    expect(map.entry_points).toHaveLength(1)
    expect(map.git_security_signals).toHaveLength(1)
  })
})
```

**Step 2: Run test → FAIL**

```bash
npx vitest run tests/unit/scan-discover.test.ts
```

**Step 3: Implement**

```typescript
// src/adapters/scan/discover.ts
import { cli, Strategy } from '../../registry.js'
import type { ExecContext } from '../../types.js'
import type { EntryPoint, GitSignal, ProjectMap } from './types.js'
import { findEntryPoints } from './entrypoints.js'
import { extractSignals, SECURITY_KEYWORDS } from './git-signals.js'
import { readdir, readFile } from 'node:fs/promises'
import { join, extname } from 'node:path'
import { execFile } from 'node:child_process'
import { promisify } from 'node:util'

const execFileAsync = promisify(execFile)

const LANG_EXT_MAP: Record<string, string> = {
  '.py': 'python',
  '.js': 'javascript',
  '.ts': 'typescript',
  '.tsx': 'typescript',
  '.jsx': 'javascript',
  '.java': 'java',
  '.php': 'php',
  '.go': 'go',
  '.rs': 'rust',
  '.rb': 'ruby',
}

const FRAMEWORK_PATTERNS: Array<{ pattern: RegExp; name: string }> = [
  { pattern: /from\s+flask\s+import|import\s+flask/i, name: 'flask' },
  { pattern: /from\s+fastapi\s+import|import\s+fastapi/i, name: 'fastapi' },
  { pattern: /from\s+django/i, name: 'django' },
  { pattern: /from\s+rest_framework/i, name: 'django-rest-framework' },
  { pattern: /require\s*\(\s*['"]express['"]\)|from\s+['"]express['"]/i, name: 'express' },
  { pattern: /@nestjs\/|from\s+['"]@nestjs/i, name: 'nestjs' },
  { pattern: /@SpringBoot|@RestController|import\s+org\.springframework/i, name: 'spring' },
  { pattern: /use\s+Illuminate|Route::/i, name: 'laravel' },
  { pattern: /from\s+['"]react['"]/i, name: 'react' },
  { pattern: /from\s+['"]vue['"]/i, name: 'vue' },
  { pattern: /from\s+['"]next/i, name: 'nextjs' },
]

const SKIP_DIRS = new Set([
  'node_modules', '.git', '__pycache__', '.venv', 'venv',
  'dist', 'build', '.next', 'vendor', 'target',
])

const SOURCE_EXTENSIONS = new Set(Object.keys(LANG_EXT_MAP))

export function detectLanguages(files: string[]): string[] {
  const langs = new Set<string>()
  for (const file of files) {
    const ext = extname(file).toLowerCase()
    const lang = LANG_EXT_MAP[ext]
    if (lang) langs.add(lang)
  }
  return [...langs]
}

export function detectFrameworks(contents: Map<string, string>): string[] {
  const frameworks = new Set<string>()
  for (const [, content] of contents) {
    for (const { pattern, name } of FRAMEWORK_PATTERNS) {
      if (pattern.test(content)) {
        frameworks.add(name)
      }
    }
  }
  return [...frameworks]
}

export function buildProjectMap(input: {
  path: string
  languages: string[]
  frameworks: string[]
  entryPoints: EntryPoint[]
  gitSignals: GitSignal[]
  sourceFiles: string[]
}): ProjectMap {
  return {
    path: input.path,
    languages: input.languages,
    frameworks: input.frameworks,
    entry_points: input.entryPoints,
    git_security_signals: input.gitSignals,
    source_files: input.sourceFiles,
  }
}

async function walkSourceFiles(dir: string, maxDepth = 10): Promise<string[]> {
  if (maxDepth <= 0) return []
  const files: string[] = []

  try {
    const entries = await readdir(dir, { withFileTypes: true })
    for (const entry of entries) {
      if (entry.name.startsWith('.') && entry.name !== '.') continue
      if (SKIP_DIRS.has(entry.name)) continue

      const fullPath = join(dir, entry.name)
      if (entry.isDirectory()) {
        const sub = await walkSourceFiles(fullPath, maxDepth - 1)
        files.push(...sub)
      } else if (SOURCE_EXTENSIONS.has(extname(entry.name).toLowerCase())) {
        files.push(fullPath)
      }
    }
  } catch {
    // Skip inaccessible dirs
  }

  return files
}

async function getGitCommits(repoPath: string, maxCommits: number) {
  try {
    const { stdout } = await execFileAsync(
      'git',
      ['log', `--max-count=${maxCommits}`, '--format=%H%x00%s', '--name-only'],
      { cwd: repoPath, maxBuffer: 10 * 1024 * 1024 },
    )

    const commits: Array<{ hash: string; message: string; files: string[] }> = []
    const blocks = stdout.trim().split('\n\n')

    for (const block of blocks) {
      const lines = block.split('\n').filter(Boolean)
      if (lines.length === 0) continue

      const [headerLine, ...fileLines] = lines
      const sepIdx = headerLine.indexOf('\0')
      if (sepIdx === -1) continue

      commits.push({
        hash: headerLine.slice(0, sepIdx),
        message: headerLine.slice(sepIdx + 1),
        files: fileLines.filter(f => f.trim().length > 0),
      })
    }

    return commits
  } catch {
    return []
  }
}

cli({
  provider: 'scan',
  name: 'discover',
  description: 'Build security-focused project map: languages, frameworks, entry points, git signals',
  strategy: Strategy.FREE,
  args: {
    path: { type: 'string', required: true, help: 'Path to project root' },
    max_commits: { type: 'number', required: false, default: 80, help: 'Max git commits to scan' },
  },
  columns: ['field', 'value'],
  timeout: 120,

  async func(ctx: ExecContext, args: Record<string, unknown>): Promise<unknown> {
    const repoPath = args.path as string
    const maxCommits = (args.max_commits as number) ?? 80

    ctx.log.step(1, 5, 'Scanning source files')
    const files = await walkSourceFiles(repoPath)
    const relativeFiles = files.map(f => f.replace(repoPath + '/', ''))
    ctx.log.verbose(`Found ${files.length} source files`)

    ctx.log.step(2, 5, 'Detecting languages')
    const languages = detectLanguages(relativeFiles)

    ctx.log.step(3, 5, 'Detecting frameworks')
    // Read a sample of files for framework detection
    const contentMap = new Map<string, string>()
    const sampleFiles = files.slice(0, 200)
    await Promise.all(
      sampleFiles.map(async f => {
        try {
          const content = await readFile(f, 'utf-8')
          contentMap.set(f, content)
        } catch { /* skip */ }
      }),
    )
    const frameworks = detectFrameworks(contentMap)

    ctx.log.step(4, 5, 'Finding entry points')
    const allEntryPoints: EntryPoint[] = []
    for (const [filePath, content] of contentMap) {
      const relativePath = filePath.replace(repoPath + '/', '')
      const fileLangs = detectLanguages([relativePath])
      const eps = findEntryPoints(relativePath, content, fileLangs)
      allEntryPoints.push(...eps)
    }

    ctx.log.step(5, 5, 'Extracting git security signals')
    const commits = await getGitCommits(repoPath, maxCommits)
    const gitSignals = extractSignals(commits, 20)

    const projectMap = buildProjectMap({
      path: repoPath,
      languages,
      frameworks,
      entryPoints: allEntryPoints,
      gitSignals,
      sourceFiles: relativeFiles,
    })

    ctx.log.info(`Discovery complete: ${languages.length} languages, ${frameworks.length} frameworks, ${allEntryPoints.length} entry points, ${gitSignals.length} git signals`)

    // Return as summary table rows
    return [
      { field: 'Languages', value: languages.join(', ') || 'none detected' },
      { field: 'Frameworks', value: frameworks.join(', ') || 'none detected' },
      { field: 'Source Files', value: String(relativeFiles.length) },
      { field: 'Entry Points', value: String(allEntryPoints.length) },
      { field: 'Git Security Signals', value: String(gitSignals.length) },
      ...allEntryPoints.slice(0, 20).map(ep => ({
        field: `  ${ep.framework ?? ep.kind}`,
        value: `${ep.file}:${ep.line} ${ep.method ?? ''} ${ep.pattern ?? ''}`.trim(),
      })),
      ...gitSignals.slice(0, 10).map(sig => ({
        field: `  git`,
        value: `${sig.commit.slice(0, 7)} ${sig.message}`,
      })),
    ]
  },
})
```

**Step 4: Run test → PASS**

```bash
npx vitest run tests/unit/scan-discover.test.ts
```

**Step 5: Commit**

```bash
git add src/adapters/scan/discover.ts tests/unit/scan-discover.test.ts
git commit -m "feat(scan): add project discovery with language/framework/entrypoint detection"
```

---

## Task 7: Full Scan Orchestrator `opensec scan full`

**Files:**
- Create: `src/adapters/scan/full.ts`
- Test: `tests/unit/scan-full.test.ts`

**来源:** `secscan-orchestrator` — 端到端 pipeline

**Step 1: Write the test**

```typescript
// tests/unit/scan-full.test.ts
import { describe, it, expect } from 'vitest'
import { buildScanSummary } from '../../src/adapters/scan/full.js'
import type { RawFinding } from '../../src/adapters/scan/types.js'

describe('buildScanSummary', () => {
  it('counts findings by severity', () => {
    const findings: RawFinding[] = [
      { rule_id: 'a', severity: 'critical', message: '', file_path: '', start_line: 0, cwe: '', tools_used: [] },
      { rule_id: 'b', severity: 'high', message: '', file_path: '', start_line: 0, cwe: '', tools_used: [] },
      { rule_id: 'c', severity: 'high', message: '', file_path: '', start_line: 0, cwe: '', tools_used: [] },
      { rule_id: 'd', severity: 'medium', message: '', file_path: '', start_line: 0, cwe: '', tools_used: [] },
    ]
    const summary = buildScanSummary(findings, 5000)
    expect(summary.total).toBe(4)
    expect(summary.critical).toBe(1)
    expect(summary.high).toBe(2)
    expect(summary.medium).toBe(1)
    expect(summary.low).toBe(0)
    expect(summary.duration_ms).toBe(5000)
  })

  it('handles empty findings', () => {
    const summary = buildScanSummary([], 1000)
    expect(summary.total).toBe(0)
  })
})
```

**Step 2: Run test → FAIL**

```bash
npx vitest run tests/unit/scan-full.test.ts
```

**Step 3: Implement**

```typescript
// src/adapters/scan/full.ts
import { cli, Strategy } from '../../registry.js'
import type { ExecContext } from '../../types.js'
import type { RawFinding } from './types.js'
import {
  parseSemgrepOutput,
  parseGitleaksOutput,
  parseNpmAuditOutput,
  normalizeFindings,
  deduplicateFindings,
} from './analyze.js'
import { buildJsonReport, buildSarifReport, buildMarkdownReport } from './report.js'
import { mkdir, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { execFile } from 'node:child_process'
import { promisify } from 'node:util'

const execFileAsync = promisify(execFile)

export function buildScanSummary(
  findings: RawFinding[],
  durationMs: number,
): {
  total: number
  critical: number
  high: number
  medium: number
  low: number
  duration_ms: number
} {
  return {
    total: findings.length,
    critical: findings.filter(f => f.severity === 'critical').length,
    high: findings.filter(f => f.severity === 'high').length,
    medium: findings.filter(f => f.severity === 'medium').length,
    low: findings.filter(f => f.severity === 'low').length,
    duration_ms: durationMs,
  }
}

async function toolExists(name: string): Promise<boolean> {
  try {
    await execFileAsync('which', [name])
    return true
  } catch {
    return false
  }
}

cli({
  provider: 'scan',
  name: 'full',
  description: 'Run full security scan pipeline: discover → analyze → report',
  strategy: Strategy.FREE,
  args: {
    path: { type: 'string', required: true, help: 'Path to project root' },
    output_dir: { type: 'string', required: false, default: './scan-results', help: 'Output directory for reports' },
  },
  columns: ['stage', 'status', 'detail'],
  timeout: 600,

  async func(ctx: ExecContext, args: Record<string, unknown>): Promise<unknown> {
    const repoPath = args.path as string
    const outputDir = (args.output_dir as string) ?? './scan-results'
    const startTime = Date.now()

    const stages: Array<{ stage: string; status: string; detail: string }> = []

    // Stage 1: Discovery (lightweight — just report what's found)
    ctx.log.step(1, 3, 'Discovery')
    stages.push({ stage: 'Discovery', status: 'running', detail: '' })

    // Stage 2: Analysis
    ctx.log.step(2, 3, 'Analysis')
    const allFindings: RawFinding[] = []

    // Run available tools in parallel
    const tasks: Array<Promise<{ tool: string; findings: RawFinding[] }>> = []

    if (await toolExists('semgrep')) {
      tasks.push(
        (async () => {
          try {
            const { stdout } = await execFileAsync(
              'semgrep', ['scan', '--json', '--config', 'auto', repoPath],
              { maxBuffer: 50 * 1024 * 1024, timeout: 120_000 },
            )
            return { tool: 'semgrep', findings: parseSemgrepOutput(JSON.parse(stdout)) }
          } catch {
            return { tool: 'semgrep', findings: [] }
          }
        })(),
      )
    }

    if (await toolExists('gitleaks')) {
      tasks.push(
        (async () => {
          try {
            const { stdout } = await execFileAsync(
              'gitleaks', ['detect', '--source', repoPath, '--report-format', 'json', '--report-path', '/dev/stdout', '--no-banner'],
              { maxBuffer: 10 * 1024 * 1024, timeout: 60_000 },
            )
            return { tool: 'gitleaks', findings: parseGitleaksOutput(JSON.parse(stdout || '[]')) }
          } catch {
            return { tool: 'gitleaks', findings: [] }
          }
        })(),
      )
    }

    const results = await Promise.allSettled(tasks)
    const toolsRun: string[] = []

    for (const r of results) {
      if (r.status === 'fulfilled') {
        allFindings.push(...r.value.findings)
        toolsRun.push(r.value.tool)
      }
    }

    const deduped = deduplicateFindings(normalizeFindings(allFindings))
    stages[0] = { stage: 'Discovery', status: 'done', detail: `scanned ${repoPath}` }
    stages.push({ stage: 'Analysis', status: 'done', detail: `${deduped.length} findings from ${toolsRun.join(', ') || 'no tools'}` })

    // Stage 3: Report
    ctx.log.step(3, 3, 'Report')
    await mkdir(outputDir, { recursive: true })

    const durationMs = Date.now() - startTime
    const jsonReport = buildJsonReport(deduped, repoPath, durationMs)
    const sarif = buildSarifReport(deduped)
    const md = buildMarkdownReport(deduped, repoPath, durationMs)

    await Promise.all([
      writeFile(join(outputDir, 'results.json'), JSON.stringify(jsonReport, null, 2)),
      writeFile(join(outputDir, 'results.sarif'), JSON.stringify(sarif, null, 2)),
      writeFile(join(outputDir, 'results.md'), md),
    ])

    const summary = buildScanSummary(deduped, durationMs)
    stages.push({
      stage: 'Report',
      status: 'done',
      detail: `${summary.total} findings (${summary.critical}C/${summary.high}H/${summary.medium}M/${summary.low}L) → ${outputDir}`,
    })

    ctx.log.info(`Scan complete in ${(durationMs / 1000).toFixed(1)}s: ${summary.total} findings`)

    return stages
  },
})
```

**Step 4: Run test → PASS**

```bash
npx vitest run tests/unit/scan-full.test.ts
```

**Step 5: Commit**

```bash
git add src/adapters/scan/full.ts tests/unit/scan-full.test.ts
git commit -m "feat(scan): add full scan orchestrator (discover → analyze → report)"
```

---

## Task 8: Build manifest 更新 & 集成测试

**Step 1: Rebuild manifest**

```bash
npm run build
```

**Step 2: Verify commands registered**

```bash
node dist/main.js list | grep scan
```

Expected: 6 commands listed under `scan` provider

**Step 3: Run all unit tests**

```bash
npx vitest run
```

Expected: All tests pass

**Step 4: Integration smoke test**

```bash
# Test entrypoints on this repo
node dist/main.js scan entrypoints --path .

# Test git-signals
node dist/main.js scan git-signals --path .

# Test discover
node dist/main.js scan discover --path .
```

**Step 5: Commit build artifacts**

```bash
git add src/cli-manifest.json
git commit -m "chore: update manifest with scan provider commands"
```

---

## 命令使用示例

```bash
# 找入口点
opensec scan entrypoints --path /path/to/repo

# 提取 git 安全信号
opensec scan git-signals --path /path/to/repo --max_commits 100

# 运行静态分析（自动检测可用工具）
opensec scan analyze --path /path/to/repo

# 指定工具
opensec scan analyze --path /path/to/repo --tools semgrep,gitleaks

# 从 findings 生成报告
opensec scan analyze --path /path/to/repo --format json > findings.json
opensec scan report --input findings.json --output_dir ./reports --formats json,sarif,markdown

# 全量扫描（一键）
opensec scan full --path /path/to/repo --output_dir ./scan-results

# 项目发现
opensec scan discover --path /path/to/repo
```

---

## 未迁移的 Skills（Phase 3, 需 Claude API）

| Skill | 原因 | 未来方案 |
|---|---|---|
| secscan-semantic-hunter | 需要 LLM 做 source-to-sink 推理 | 接入 Claude API，作为 `opensec scan semantic` |
| secscan-triage | 需要 attacker/defender 对抗验证 | 接入 Claude API，作为 `opensec scan triage` |
| secscan-context-builder | 为 LLM 构建上下文 | 作为内部模块支撑 semantic/triage |
| secscan-triage-memory | 持久化学习 | SQLite 本地存储 + `opensec scan memory` |
| secscan-benchmark | 需要 ground truth 数据集 | 作为 `opensec scan benchmark` 独立子系统 |

---

## 风险与注意

1. **外部工具依赖** — semgrep/gitleaks 未安装时优雅降级，不 abort
2. **大仓库性能** — walkDir 限制 maxDepth=10，文件采样 200 个做框架检测
3. **正则匹配精度** — entrypoint-finder 是 best-effort，不等于 AST 解析
4. **SARIF 规范** — 使用 2.1.0 schema，兼容 GitHub Code Scanning
