/**
 * Entry point finder adapter.
 * Scans source files for HTTP routes, RPC handlers, and other entry points
 * using regex pattern matching. Supports Flask, FastAPI, Django, Express,
 * NestJS, Spring, and Laravel.
 *
 * Strategy: FREE — no external tools required.
 */

import { cli, Strategy } from '../../registry.js'
import type { ExecContext } from '../../types.js'
import type { EntryPoint, EntryPointKind } from './types.js'
import { readdir, readFile } from 'node:fs/promises'
import { join, extname } from 'node:path'

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

/**
 * Route patterns for each framework.
 * Flask and FastAPI share Python decorator syntax; framework detection
 * is handled in findEntryPoints via import inspection so they don't
 * double-match.
 */
export const ROUTE_PATTERNS: RoutePattern[] = [
  // Flask — @app.route / @app.get / etc.
  {
    regex: /@\w+\.(route|get|post|put|delete|patch)\s*\(\s*['"]([^'"]+)['"]/gm,
    kind: 'http_route',
    framework: 'flask',
    languages: ['python'],
    extractRoute: (m) => m[2],
    extractMethod: (m) => m[1] === 'route' ? undefined : m[1]?.toUpperCase(),
  },
  // FastAPI — identical decorator syntax, distinguished by import
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
    regex: /@(GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping)\s*\(\s*(?:value\s*=\s*)?['"]([^'"]+)['"]/gm,
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

/**
 * Detect the Python framework used in a file by checking import statements.
 * Returns 'flask', 'fastapi', or 'unknown'.
 */
function detectPythonFramework(content: string): 'flask' | 'fastapi' | 'django' | 'unknown' {
  if (/from\s+fastapi\b|import\s+fastapi\b/i.test(content)) return 'fastapi'
  if (/from\s+flask\b|import\s+flask\b/i.test(content)) return 'flask'
  if (/from\s+django\b|import\s+django\b/i.test(content)) return 'django'
  return 'unknown'
}

/**
 * Find entry points (HTTP routes, RPC handlers, etc.) in a single file.
 * Exported for use by discover.ts and other adapters.
 */
export function findEntryPoints(
  filePath: string,
  content: string,
  languages: string[],
): EntryPoint[] {
  if (isTestFile(filePath)) return []

  const results: EntryPoint[] = []
  const seen = new Set<string>()

  // Determine which Python framework to use so Flask/FastAPI don't double-match
  const pyFramework = languages.includes('python')
    ? detectPythonFramework(content)
    : null

  for (const pattern of ROUTE_PATTERNS) {
    if (!pattern.languages.some(l => languages.includes(l))) continue

    // Avoid Flask/FastAPI double-match: only run the pattern matching the detected framework
    if (languages.includes('python') && (pattern.framework === 'flask' || pattern.framework === 'fastapi')) {
      if (pyFramework === 'flask' && pattern.framework !== 'flask') continue
      if (pyFramework === 'fastapi' && pattern.framework !== 'fastapi') continue
      // If pyFramework is 'unknown' or 'django', skip both flask and fastapi decorator patterns
      if (pyFramework !== 'flask' && pyFramework !== 'fastapi') continue
    }

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
