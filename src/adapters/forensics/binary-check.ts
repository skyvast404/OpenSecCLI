/**
 * Binary security protections checker adapter.
 * Wraps: checksec
 * Source: pentest-ctf-binary
 */

import { cli, Strategy } from '../../registry.js'
import type { ExecContext } from '../../types.js'
import { runTool, findAvailableTool } from '../_utils/tool-runner.js'

interface ChecksecJsonEntry {
  relro?: string
  canary?: string
  nx?: string
  pie?: string
  rpath?: string
  runpath?: string
  symbols?: string
  fortify_source?: string
  fortified?: string
  fortifiable?: string
  [key: string]: unknown
}

const PROTECTION_LABELS: Record<string, string> = {
  relro: 'RELRO',
  canary: 'Stack Canary',
  nx: 'NX (No-Execute)',
  pie: 'PIE (Position Independent)',
  rpath: 'RPATH',
  runpath: 'RUNPATH',
  symbols: 'Symbols',
  fortify_source: 'Fortify Source',
  fortified: 'Fortified Functions',
  fortifiable: 'Fortifiable Functions',
}

export function normalizeStatus(value: string): string {
  const lower = value.toLowerCase().trim()
  if (
    lower === 'yes' ||
    lower === 'full' ||
    lower === 'enabled' ||
    lower === 'full relro' ||
    lower === 'true'
  ) {
    return 'ENABLED'
  }
  if (
    lower === 'no' ||
    lower === 'disabled' ||
    lower === 'none' ||
    lower === 'no relro' ||
    lower === 'false'
  ) {
    return 'DISABLED'
  }
  if (lower === 'partial' || lower === 'partial relro') {
    return 'PARTIAL'
  }
  return value.toUpperCase()
}

export function parseChecksecJson(stdout: string): Record<string, unknown>[] {
  try {
    const data = JSON.parse(stdout) as Record<string, ChecksecJsonEntry>
    // checksec JSON format: { "filename": { relro: "...", canary: "...", ... } }
    const entries = Object.values(data)
    if (entries.length === 0) return []

    const entry = entries[0]
    return Object.entries(entry)
      .filter(([key]) => key in PROTECTION_LABELS)
      .map(([key, value]) => ({
        protection: PROTECTION_LABELS[key] ?? key,
        status: normalizeStatus(String(value)),
        detail: String(value),
      }))
  } catch {
    return []
  }
}

export function parseChecksecText(stdout: string): Record<string, unknown>[] {
  const lines = stdout.split('\n').filter((l) => l.trim().length > 0)
  const rows: Record<string, unknown>[] = []

  for (const line of lines) {
    // Skip header lines
    if (line.includes('RELRO') && line.includes('CANARY')) continue
    if (line.startsWith('*')) continue

    // Try to parse "key: value" or tabular format
    const colonMatch = line.match(/^\s*(.+?):\s*(.+)$/)
    if (colonMatch) {
      rows.push({
        protection: colonMatch[1].trim(),
        status: normalizeStatus(colonMatch[2].trim()),
        detail: colonMatch[2].trim(),
      })
    }
  }

  return rows
}

cli({
  provider: 'forensics',
  name: 'binary-check',
  description: 'Check binary security protections (RELRO, canary, NX, PIE) using checksec',
  strategy: Strategy.FREE,
  args: {
    file: { type: 'string', required: true, help: 'Path to binary file' },
  },
  columns: ['protection', 'status', 'detail'],
  timeout: 60,

  async func(ctx: ExecContext, args: Record<string, unknown>) {
    const filePath = args.file as string

    const tool = await findAvailableTool(['checksec'])
    if (!tool) {
      throw new Error(
        'checksec is not installed. Install it to use this command: ' +
          'https://github.com/slimm609/checksec.sh',
      )
    }

    // Try JSON output first
    try {
      const result = await runTool({
        tool: 'checksec',
        args: ['--json', '--file', filePath],
        allowNonZero: true,
      })
      const rows = parseChecksecJson(result.stdout)
      if (rows.length > 0) {
        ctx.log.info(`Binary check: ${rows.length} protections analyzed for ${filePath}`)
        return rows
      }
    } catch {
      ctx.log.verbose('JSON output failed, falling back to text parsing')
    }

    // Fallback to text output
    const result = await runTool({
      tool: 'checksec',
      args: ['--file', filePath],
      allowNonZero: true,
    })
    const rows = parseChecksecText(result.stdout)
    ctx.log.info(`Binary check: ${rows.length} protections analyzed for ${filePath}`)
    return rows
  },
})
