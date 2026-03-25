/**
 * Multi-tool file analysis adapter.
 * Runs: file, exiftool, strings, binwalk in parallel via Promise.allSettled
 * Source: pentest-ctf-forensics
 */

import { cli, Strategy } from '../../registry.js'
import type { ExecContext } from '../../types.js'
import { runTool, checkToolInstalled } from '../_utils/tool-runner.js'

const INTERESTING_PATTERNS = [
  /https?:\/\/\S+/i,
  /password/i,
  /secret/i,
  /key[=:]/i,
  /flag\{/i,
  /admin/i,
  /token/i,
  /api[_-]?key/i,
  /private/i,
  /credential/i,
  /auth/i,
  /BEGIN\s+(RSA|DSA|EC|OPENSSH|PGP)/i,
]

const EXIFTOOL_SKIP_FIELDS = new Set([
  'ExifToolVersion',
  'FileName',
  'Directory',
  'FileModifyDate',
  'FileAccessDate',
  'FileInodeChangeDate',
  'FilePermissions',
  'SourceFile',
])

export function filterInterestingStrings(raw: string): Record<string, unknown>[] {
  const lines = raw.split('\n').filter((l) => l.trim().length >= 4)
  const matches: Record<string, unknown>[] = []

  for (const line of lines) {
    const trimmed = line.trim()
    for (const pattern of INTERESTING_PATTERNS) {
      if (pattern.test(trimmed)) {
        matches.push({
          tool: 'strings',
          key: pattern.source.replace(/[\\()]/g, ''),
          value: trimmed.length > 200 ? trimmed.slice(0, 200) + '...' : trimmed,
        })
        break
      }
    }
  }

  return matches.slice(0, 100)
}

export function parseExiftoolOutput(stdout: string): Record<string, unknown>[] {
  try {
    const data = JSON.parse(stdout) as Record<string, unknown>[]
    const entry = Array.isArray(data) ? data[0] : data
    if (!entry || typeof entry !== 'object') return []

    return Object.entries(entry as Record<string, unknown>)
      .filter(([key]) => !EXIFTOOL_SKIP_FIELDS.has(key))
      .map(([key, value]) => ({
        tool: 'exiftool',
        key,
        value: String(value),
      }))
  } catch {
    return []
  }
}

export function parseFileOutput(stdout: string): Record<string, unknown>[] {
  const trimmed = stdout.trim()
  if (!trimmed) return []

  // "filename: type description" format
  const colonIdx = trimmed.indexOf(':')
  const description = colonIdx >= 0 ? trimmed.slice(colonIdx + 1).trim() : trimmed

  return [{ tool: 'file', key: 'type', value: description }]
}

export function parseBinwalkOutput(stdout: string): Record<string, unknown>[] {
  const lines = stdout.split('\n').filter((l) => l.trim().length > 0)
  // Skip header lines (DECIMAL, HEXADECIMAL, DESCRIPTION)
  const dataLines = lines.filter((l) => /^\d+/.test(l.trim()))

  return dataLines.map((line) => {
    const parts = line.trim().split(/\s{2,}/)
    return {
      tool: 'binwalk',
      key: parts[0] ?? '',
      value: parts.slice(1).join(' '),
    }
  })
}

cli({
  provider: 'forensics',
  name: 'file-analyze',
  description: 'Analyze a file using file, exiftool, strings, and binwalk in parallel',
  strategy: Strategy.FREE,
  args: {
    file: { type: 'string', required: true, help: 'Path to file to analyze' },
  },
  columns: ['tool', 'key', 'value'],
  timeout: 120,

  async func(ctx: ExecContext, args: Record<string, unknown>) {
    const filePath = args.file as string
    const rows: Record<string, unknown>[] = []

    const tools = ['file', 'exiftool', 'strings', 'binwalk'] as const

    const available = await Promise.all(
      tools.map(async (t) => ({ name: t, installed: await checkToolInstalled(t) })),
    )

    const installedTools = available.filter((t) => t.installed).map((t) => t.name)
    ctx.log.info(`Running file analysis with: ${installedTools.join(', ')}`)

    if (installedTools.length === 0) {
      throw new Error(
        'No analysis tools available. Install at least one of: file, exiftool, strings, binwalk',
      )
    }

    const runners = installedTools.map(async (tool) => {
      switch (tool) {
        case 'file': {
          const result = await runTool({ tool: 'file', args: [filePath] })
          return parseFileOutput(result.stdout)
        }
        case 'exiftool': {
          const result = await runTool({ tool: 'exiftool', args: ['-json', filePath] })
          return parseExiftoolOutput(result.stdout)
        }
        case 'strings': {
          const result = await runTool({ tool: 'strings', args: [filePath] })
          return filterInterestingStrings(result.stdout)
        }
        case 'binwalk': {
          const result = await runTool({ tool: 'binwalk', args: [filePath] })
          return parseBinwalkOutput(result.stdout)
        }
        default:
          return []
      }
    })

    const results = await Promise.allSettled(runners)

    for (const result of results) {
      if (result.status === 'fulfilled') {
        rows.push(...result.value)
      }
    }

    ctx.log.info(`File analysis found ${rows.length} items for ${filePath}`)
    return rows
  },
})
