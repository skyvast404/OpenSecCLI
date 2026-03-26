/**
 * Security-focused code context builder for LLM analysis.
 * Given a target file:line, finds related files prioritized by security
 * relevance (sink keywords, security-related filenames) within a char budget.
 *
 * Strategy: FREE — pure TypeScript, no external tools required.
 */

import { cli, Strategy } from '../../registry.js'
import type { AdapterResult, ExecContext } from '../../types.js'
import { readFileSync, statSync } from 'node:fs'
import { resolve, dirname, extname, join, relative } from 'node:path'
import { walkDir, SKIP_DIRS } from '../../utils/fs-walk.js'

// --- Constants ---

export const SINK_KEYWORDS = [
  'query', 'exec', 'execute', 'render', 'redirect',
  'deserialize', 'unserialize', 'token', 'session',
  'password', 'secret', 'eval', 'system', 'popen',
  'subprocess', 'innerHTML', 'outerHTML', 'document.write',
  'dangerouslySetInnerHTML', 'raw', 'safe', 'mark_safe',
] as const

export const SECURITY_FILE_NAMES = [
  'auth', 'db', 'database', 'user', 'service', 'helper', 'query',
] as const

const SOURCE_EXTENSIONS = new Set([
  '.ts', '.tsx', '.js', '.jsx', '.py', '.java', '.go', '.rb', '.php',
])

// --- Import Parsing ---

export interface ImportInfo {
  raw: string
  resolved: string
}

const IMPORT_PATTERNS = [
  // ES import: import ... from 'path' or import 'path'
  /import\s+(?:[\s\S]*?\s+from\s+)?['"]([^'"]+)['"]/g,
  // CommonJS: require('path')
  /require\s*\(\s*['"]([^'"]+)['"]\s*\)/g,
  // Python: from path import ...
  /from\s+([\w.]+)\s+import/g,
]

/**
 * Extract raw import specifiers from file content (no filesystem resolution).
 * Supports: import ... from '...', require('...'), from ... import ...
 */
export function parseImportSpecifiers(content: string): string[] {
  const seen = new Set<string>()
  const result: string[] = []

  for (const pattern of IMPORT_PATTERNS) {
    const regex = new RegExp(pattern.source, pattern.flags)
    let match: RegExpExecArray | null

    while ((match = regex.exec(content)) !== null) {
      const raw = match[1]
      if (seen.has(raw)) continue
      seen.add(raw)
      result.push(raw)
    }
  }

  return result
}

/**
 * Parse import statements and resolve them to file paths.
 * Returns only imports that resolve to readable files on disk.
 */
export function parseImports(content: string, filePath: string): ImportInfo[] {
  const dir = dirname(filePath)
  const specifiers = parseImportSpecifiers(content)

  const imports: ImportInfo[] = []
  for (const raw of specifiers) {
    const resolved = resolveImportPath(raw, dir)
    if (resolved) {
      imports.push({ raw, resolved })
    }
  }

  return imports
}

/**
 * Attempt to resolve an import specifier to a file path.
 * Returns null for node_modules / unresolvable paths.
 */
function resolveImportPath(specifier: string, fromDir: string): string | null {
  // Skip bare specifiers (node_modules packages)
  if (!specifier.startsWith('.') && !specifier.startsWith('/')) {
    // Python dotted path: convert dots to slashes
    if (/^[a-zA-Z_]\w*(\.\w+)+$/.test(specifier)) {
      const asPath = specifier.replace(/\./g, '/')
      return tryResolveFile(join(fromDir, asPath))
    }
    return null
  }

  const candidate = resolve(fromDir, specifier)
  return tryResolveFile(candidate)
}

function tryResolveFile(candidate: string): string | null {
  // Try exact path first
  if (isReadableFile(candidate)) return candidate

  // Try with common extensions
  for (const ext of SOURCE_EXTENSIONS) {
    const withExt = candidate + ext
    if (isReadableFile(withExt)) return withExt
  }

  // Try index files
  for (const ext of SOURCE_EXTENSIONS) {
    const indexFile = join(candidate, `index${ext}`)
    if (isReadableFile(indexFile)) return indexFile
  }

  return null
}

function isReadableFile(path: string): boolean {
  try {
    const stat = statSync(path)
    return stat.isFile()
  } catch {
    return false
  }
}

// --- Scoring ---

export interface ScoredFile {
  file: string
  content: string
  sinkHits: number
  nameBonus: number
  score: number
  reason: string
}

/**
 * Count sink keyword occurrences in file content.
 */
export function countSinkHits(content: string): number {
  const lower = content.toLowerCase()
  let count = 0

  for (const keyword of SINK_KEYWORDS) {
    const kw = keyword.toLowerCase()
    let idx = 0
    while ((idx = lower.indexOf(kw, idx)) !== -1) {
      count++
      idx += kw.length
    }
  }

  return count
}

/**
 * Compute filename bonus for security-related names.
 */
export function computeNameBonus(filePath: string): number {
  const lower = filePath.toLowerCase()
  let bonus = 0

  for (const name of SECURITY_FILE_NAMES) {
    if (lower.includes(name)) {
      bonus += 5
    }
  }

  return bonus
}

function buildReason(sinkHits: number, nameBonus: number, isDirectImport: boolean): string {
  const parts: string[] = []
  if (isDirectImport) parts.push('direct import')
  if (sinkHits > 0) parts.push(`${sinkHits} sink keywords`)
  if (nameBonus > 0) parts.push('security-related filename')
  return parts.length > 0 ? parts.join(', ') : 'related file'
}

// --- Section Building ---

export interface ContextSection {
  type: string
  file: string
  lines: number
  reason: string
  sink_hits: number
  [key: string]: unknown
}

/**
 * Expand imports up to the given depth, collecting scored file info.
 */
function expandImports(
  startFile: string,
  projectRoot: string,
  maxDepth: number,
): ScoredFile[] {
  const visited = new Set<string>()
  const result: ScoredFile[] = []

  function walk(filePath: string, depth: number, isDirectImport: boolean): void {
    const absPath = resolve(filePath)
    if (visited.has(absPath)) return
    visited.add(absPath)

    let content: string
    try {
      content = readFileSync(absPath, 'utf-8')
    } catch {
      return
    }

    const sinkHits = countSinkHits(content)
    const relPath = relative(projectRoot, absPath)
    const nameBonus = computeNameBonus(relPath)
    const score = sinkHits + nameBonus + (isDirectImport ? 10 : 0)
    const reason = buildReason(sinkHits, nameBonus, isDirectImport)

    result.push({
      file: relPath,
      content,
      sinkHits,
      nameBonus,
      score,
      reason,
    })

    if (depth < maxDepth) {
      const imports = parseImports(content, absPath)
      for (const imp of imports) {
        walk(imp.resolved, depth + 1, false)
      }
    }
  }

  walk(startFile, 0, false)
  return result
}

// --- Main Logic ---

export function buildContext(
  targetPath: string,
  projectRoot: string,
  budget: number,
): ContextSection[] {
  const absTarget = resolve(projectRoot, targetPath)

  // Read target file
  let targetContent: string
  try {
    targetContent = readFileSync(absTarget, 'utf-8')
  } catch (error) {
    throw new Error(`Cannot read target file: ${(error as Error).message}`)
  }

  // Expand imports up to 2 levels
  const files = expandImports(absTarget, projectRoot, 2)

  // Sort by score descending
  const sorted = [...files].sort((a, b) => b.score - a.score)

  // Truncate to budget
  const sections: ContextSection[] = []
  let usedChars = 0

  for (const f of sorted) {
    const contentLen = f.content.length
    if (usedChars + contentLen > budget) {
      // Include partial if we have room for at least 500 chars
      if (budget - usedChars >= 500) {
        const truncatedLen = budget - usedChars
        sections.push({
          type: 'truncated',
          file: f.file,
          lines: f.content.slice(0, truncatedLen).split('\n').length,
          reason: f.reason,
          sink_hits: f.sinkHits,
        })
        usedChars += truncatedLen
      }
      break
    }

    sections.push({
      type: f.file === relative(projectRoot, absTarget) ? 'target' : 'context',
      file: f.file,
      lines: f.content.split('\n').length,
      reason: f.reason,
      sink_hits: f.sinkHits,
    })
    usedChars += contentLen
  }

  return sections
}

// --- CLI Registration ---

cli({
  provider: 'scan',
  name: 'context-builder',
  description:
    'Build security-focused code context bundles for LLM analysis',
  strategy: Strategy.FREE,
  domain: 'code-security',
  args: {
    path: { type: 'string', required: true, help: 'Project root path' },
    target: {
      type: 'string',
      required: true,
      help: 'Target file:line (e.g., src/api.py:42)',
    },
    mode: {
      type: 'string',
      required: false,
      default: 'entry_point',
      choices: ['discovery', 'entry_point', 'finding'],
      help: 'Context mode (default: entry_point)',
    },
    budget: {
      type: 'number',
      required: false,
      default: 200000,
      help: 'Character budget (default: 200000)',
    },
  },
  columns: ['type', 'file', 'lines', 'reason', 'sink_hits'],

  async func(ctx: ExecContext, args: Record<string, unknown>): Promise<AdapterResult> {
    const projectRoot = args.path as string
    const targetArg = args.target as string
    const budget = (args.budget as number) ?? 200000

    // Parse target — strip optional :line suffix
    const targetFile = targetArg.includes(':')
      ? targetArg.slice(0, targetArg.lastIndexOf(':'))
      : targetArg

    ctx.log.info(`Building context for ${targetFile} (budget: ${budget} chars)`)

    try {
      const sections = buildContext(targetFile, projectRoot, budget)

      if (sections.length === 0) {
        ctx.log.warn('No context sections generated')
        return []
      }

      const totalLines = sections.reduce((sum, s) => sum + s.lines, 0)
      ctx.log.info(
        `Built ${sections.length} sections (${totalLines} total lines)`,
      )

      return sections
    } catch (error) {
      throw new Error(`Context build failed: ${(error as Error).message}`)
    }
  },
})
