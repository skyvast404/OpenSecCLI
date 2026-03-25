/**
 * Multi-tool static analysis runner.
 * Coordinates semgrep and gitleaks in parallel.
 * Normalizes and deduplicates findings into a unified RawFinding format.
 */

import { cli, Strategy } from '../../registry.js'
import type { ExecContext } from '../../types.js'
import type { RawFinding, Severity, PhaseMetric } from './types.js'
import { checkToolInstalled, runTool } from '../_utils/tool-runner.js'

// --- Severity Mapping ---

const SEMGREP_SEVERITY_MAP: Record<string, Severity> = {
  ERROR: 'high',
  WARNING: 'medium',
  INFO: 'low',
}

// --- Parsers ---

export function parseSemgrepOutput(output: { results: Array<Record<string, unknown>> }): RawFinding[] {
  return (output.results ?? []).map((r: Record<string, unknown>) => {
    const extra = (r.extra as Record<string, unknown>) ?? {}
    const metadata = (extra.metadata as Record<string, unknown>) ?? {}
    const cweList = (metadata.cwe as string[]) ?? []
    const rawCwe = cweList[0] ?? ''
    const cwe = rawCwe.match(/CWE-\d+/)?.[0] ?? ''

    return {
      rule_id: r.check_id as string,
      severity: SEMGREP_SEVERITY_MAP[extra.severity as string] ?? 'medium',
      message: (extra.message as string) ?? '',
      file_path: r.path as string,
      start_line: (r.start as Record<string, number>)?.line ?? 0,
      cwe,
      tools_used: ['semgrep'],
    }
  })
}

export function parseGitleaksOutput(output: Array<Record<string, unknown>>): RawFinding[] {
  return output.map((r) => ({
    rule_id: r.RuleID as string,
    severity: 'high' as Severity,
    message: (r.Description as string) ?? 'Hardcoded secret detected',
    file_path: r.File as string,
    start_line: (r.StartLine as number) ?? 0,
    cwe: 'CWE-798',
    tools_used: ['gitleaks'],
  }))
}

// --- Normalize & Dedup ---

export function normalizeFindings(findings: RawFinding[]): RawFinding[] {
  return findings.map((f) => ({
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

async function runSemgrep(repoPath: string, ctx: ExecContext): Promise<{ findings: RawFinding[]; metric: PhaseMetric }> {
  const start = Date.now()
  try {
    const result = await runTool({
      tool: 'semgrep',
      args: ['scan', '--json', '--config', 'auto', repoPath],
      timeout: 120,
    })
    const output = JSON.parse(result.stdout)
    const findings = parseSemgrepOutput(output)
    return { findings, metric: { adapter: 'semgrep', latency_ms: Date.now() - start, findings_count: findings.length, status: 'completed' } }
  } catch (error) {
    ctx.log.warn(`Semgrep failed: ${(error as Error).message}`)
    return { findings: [], metric: { adapter: 'semgrep', latency_ms: Date.now() - start, findings_count: 0, status: 'failed', error: (error as Error).message } }
  }
}

async function runGitleaks(repoPath: string, ctx: ExecContext): Promise<{ findings: RawFinding[]; metric: PhaseMetric }> {
  const start = Date.now()
  try {
    const result = await runTool({
      tool: 'gitleaks',
      args: ['detect', '--source', repoPath, '--report-format', 'json', '--report-path', '/dev/stdout', '--no-banner'],
      timeout: 60,
      allowNonZero: true,
    })
    const output = JSON.parse(result.stdout || '[]')
    const findings = parseGitleaksOutput(output)
    return { findings, metric: { adapter: 'gitleaks', latency_ms: Date.now() - start, findings_count: findings.length, status: 'completed' } }
  } catch (error) {
    ctx.log.warn(`Gitleaks failed: ${(error as Error).message}`)
    return { findings: [], metric: { adapter: 'gitleaks', latency_ms: Date.now() - start, findings_count: 0, status: 'failed', error: (error as Error).message } }
  }
}

// --- CLI Registration ---

cli({
  provider: 'scan',
  name: 'analyze',
  description:
    'Run static security analysis (semgrep, gitleaks) on a codebase',
  strategy: Strategy.FREE,
  args: {
    path: { type: 'string', required: true, help: 'Path to project root' },
    tools: {
      type: 'string',
      required: false,
      default: 'auto',
      help: 'Comma-separated tools: semgrep,gitleaks (default: auto-detect)',
    },
  },
  columns: [
    'rule_id',
    'severity',
    'file_path',
    'start_line',
    'cwe',
    'message',
    'tools_used',
  ],
  timeout: 300,

  async func(ctx: ExecContext, args: Record<string, unknown>): Promise<unknown> {
    const repoPath = args.path as string
    const toolsArg = (args.tools as string) ?? 'auto'

    // Detect available tools
    const available: Record<string, boolean> = {}
    const toolNames = ['semgrep', 'gitleaks']

    await Promise.all(
      toolNames.map(async (t) => {
        available[t] = await checkToolInstalled(t)
      }),
    )

    const requestedTools =
      toolsArg === 'auto'
        ? toolNames.filter((t) => available[t])
        : toolsArg.split(',').map((t) => t.trim())

    ctx.log.info(`Running analysis with: ${requestedTools.join(', ')}`)

    // Run all available tools in parallel
    const runners: Array<Promise<{ findings: RawFinding[]; metric: PhaseMetric }>> = []

    if (requestedTools.includes('semgrep') && available.semgrep) {
      runners.push(runSemgrep(repoPath, ctx))
    }
    if (requestedTools.includes('gitleaks') && available.gitleaks) {
      runners.push(runGitleaks(repoPath, ctx))
    }

    if (runners.length === 0) {
      ctx.log.warn(
        'No analysis tools available. Install semgrep or gitleaks.',
      )
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

    ctx.log.info(
      `Analysis complete: ${deduped.length} findings (${metrics.filter((m) => m.status === 'completed').length}/${metrics.length} tools succeeded)`,
    )

    for (const m of metrics) {
      ctx.log.verbose(
        `  ${m.adapter}: ${m.status} (${m.latency_ms}ms, ${m.findings_count} findings)`,
      )
    }

    return deduped.map((f) => ({
      ...f,
      tools_used: f.tools_used.join(', '),
    }))
  },
})
