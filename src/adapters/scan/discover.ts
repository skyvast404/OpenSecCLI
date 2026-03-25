/**
 * Project discovery adapter.
 * Combines entry point finding + git signal extraction + language/framework detection
 * to build a security-focused project map.
 *
 * Strategy: FREE -- no external tools required (beyond git).
 */

import { cli, Strategy } from '../../registry.js'
import type { ExecContext } from '../../types.js'
import type { EntryPoint, GitSignal, ProjectMap } from './types.js'
import { findEntryPoints } from './entrypoints.js'
import { extractSignals } from './git-signals.js'
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

const FRAMEWORK_PATTERNS: ReadonlyArray<{ pattern: RegExp; name: string }> = [
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
        files: fileLines.filter((f: string) => f.trim().length > 0),
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
    const contentMap = new Map<string, string>()
    const sampleFiles = files.slice(0, 200)
    await Promise.all(
      sampleFiles.map(async f => {
        try {
          const content = await readFile(f, 'utf-8')
          contentMap.set(f, content)
        } catch { /* skip unreadable */ }
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

    ctx.log.info(
      `Discovery complete: ${projectMap.languages.length} languages, ` +
      `${projectMap.frameworks.length} frameworks, ` +
      `${projectMap.entry_points.length} entry points, ` +
      `${projectMap.git_security_signals.length} git signals`,
    )

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
        field: '  git',
        value: `${sig.commit.slice(0, 7)} ${sig.message}`,
      })),
    ]
  },
})
