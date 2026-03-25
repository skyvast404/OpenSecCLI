/**
 * Full scan orchestrator for OpenSecCLI.
 * Runs the complete pipeline: discover → analyze → report.
 * Coordinates all security analysis tools and produces unified reports.
 */

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
