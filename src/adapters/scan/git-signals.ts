/**
 * Git security signal extractor.
 * Parses git log output to find security-relevant commits by keyword matching.
 */

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

export interface CommitLog {
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
