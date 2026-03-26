/**
 * Full scan orchestrator for OpenSecCLI.
 * Runs the complete pipeline: discover → analyze → report.
 * Coordinates all security analysis tools and produces unified reports.
 */

import { cli, Strategy, getRegistry } from '../../registry.js'
import type { AdapterResult, ExecContext } from '../../types.js'
import type { RawFinding, Severity } from './types.js'
import { buildJsonReport, buildSarifReport, buildMarkdownReport } from './report.js'
import { mkdir, writeFile } from 'node:fs/promises'
import { join } from 'node:path'

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

cli({
  provider: 'scan',
  name: 'full',
  description: 'Run full security scan pipeline: discover → analyze → trufflehog → dep-audit → report',
  strategy: Strategy.FREE,
  domain: 'code-security',
  args: {
    path: { type: 'string', required: true, help: 'Path to project root' },
    output_dir: { type: 'string', required: false, default: './scan-results', help: 'Output directory for reports' },
  },
  columns: ['stage', 'status', 'detail'],
  timeout: 600,

  async func(ctx: ExecContext, args: Record<string, unknown>): Promise<AdapterResult> {
    const repoPath = args.path as string
    const outputDir = (args.output_dir as string) ?? './scan-results'
    const startTime = Date.now()
    const totalStages = 5

    const stages: Array<{ stage: string; status: string; detail: string }> = []
    const allFindings: RawFinding[] = []

    // Stage 1: Discovery — actually run scan/discover
    ctx.log.step(1, totalStages, 'Discovery')
    const discoverCmd = getRegistry().get('scan/discover')
    if (discoverCmd?.func) {
      try {
        const discoverResult = await discoverCmd.func(ctx, { path: repoPath })
        const resultRows = Array.isArray(discoverResult) ? discoverResult as Array<Record<string, unknown>> : []
        const summaryParts = resultRows
          .filter(r => typeof r.field === 'string' && typeof r.value === 'string' && !(r.field as string).startsWith('  '))
          .map(r => `${r.field}: ${r.value}`)
          .join(', ')
        stages.push({ stage: 'Discovery', status: 'done', detail: summaryParts || `scanned ${repoPath}` })
      } catch (error) {
        ctx.log.warn(`Discovery failed: ${(error as Error).message}`)
        stages.push({ stage: 'Discovery', status: 'failed', detail: (error as Error).message })
      }
    } else {
      stages.push({ stage: 'Discovery', status: 'skipped', detail: 'scan/discover not available' })
    }

    // Stage 2: Analysis (semgrep + gitleaks)
    ctx.log.step(2, totalStages, 'Analysis')
    const analyzeCmd = getRegistry().get('scan/analyze')
    if (analyzeCmd?.func) {
      try {
        const analyzeResult = await analyzeCmd.func(ctx, { path: repoPath, tools: 'auto' })
        if (Array.isArray(analyzeResult)) {
          for (const r of analyzeResult as Array<Record<string, unknown>>) {
            allFindings.push({
              rule_id: (r.rule_id as string) ?? '',
              severity: (r.severity as Severity) ?? 'medium',
              message: (r.message as string) ?? '',
              file_path: (r.file_path as string) ?? '',
              start_line: (r.start_line as number) ?? 0,
              cwe: (r.cwe as string) ?? '',
              tools_used: typeof r.tools_used === 'string' ? (r.tools_used as string).split(', ') : [],
            })
          }
        }
      } catch (error) {
        ctx.log.warn(`Analysis failed: ${(error as Error).message}`)
      }
    }
    stages.push({ stage: 'Analysis', status: 'done', detail: `${allFindings.length} findings` })

    // Stage 3: TruffleHog deep secret scan
    ctx.log.step(3, totalStages, 'TruffleHog Secret Scan')
    const trufflehogCmd = getRegistry().get('secrets/trufflehog-scan')
    if (trufflehogCmd?.func) {
      try {
        const secretResults = await trufflehogCmd.func(ctx, { path: repoPath })
        if (Array.isArray(secretResults)) {
          let secretCount = 0
          for (const r of secretResults as Array<Record<string, unknown>>) {
            allFindings.push({
              rule_id: `trufflehog/${(r.detector as string) ?? 'secret'}`,
              severity: (r.severity as Severity) ?? 'high',
              message: `Secret detected: ${(r.detector as string) ?? 'unknown'} ${(r.raw_preview as string) ?? ''}`.trim(),
              file_path: (r.file as string) ?? '',
              start_line: (r.line as number) ?? 0,
              cwe: 'CWE-798',
              tools_used: ['trufflehog'],
            })
            secretCount++
          }
          stages.push({ stage: 'TruffleHog', status: 'done', detail: `${secretCount} secrets found` })
        } else {
          stages.push({ stage: 'TruffleHog', status: 'done', detail: '0 secrets found' })
        }
      } catch {
        stages.push({ stage: 'TruffleHog', status: 'skipped', detail: 'trufflehog not installed or failed' })
      }
    } else {
      stages.push({ stage: 'TruffleHog', status: 'skipped', detail: 'secrets/trufflehog-scan not available' })
    }

    // Stage 4: Dependency audit
    ctx.log.step(4, totalStages, 'Dependency Audit')
    const depAuditCmd = getRegistry().get('supply-chain/dep-audit')
    if (depAuditCmd?.func) {
      try {
        const depResults = await depAuditCmd.func(ctx, { path: repoPath })
        if (Array.isArray(depResults)) {
          let depCount = 0
          for (const r of depResults as Array<Record<string, unknown>>) {
            allFindings.push({
              rule_id: `dep-audit/${(r.ecosystem as string) ?? 'unknown'}/${(r.package as string) ?? 'unknown'}`,
              severity: (r.severity as Severity) ?? 'medium',
              message: `Vulnerable dependency: ${(r.package as string) ?? ''} — ${(r.vulnerability as string) ?? ''}`.trim(),
              file_path: '',
              start_line: 0,
              cwe: '',
              tools_used: ['dep-audit'],
              metadata: { ecosystem: r.ecosystem, fix_version: r.fix_version },
            })
            depCount++
          }
          stages.push({ stage: 'Dep Audit', status: 'done', detail: `${depCount} vulnerable deps` })
        } else {
          stages.push({ stage: 'Dep Audit', status: 'done', detail: '0 vulnerable deps' })
        }
      } catch {
        stages.push({ stage: 'Dep Audit', status: 'skipped', detail: 'dep-audit not installed or failed' })
      }
    } else {
      stages.push({ stage: 'Dep Audit', status: 'skipped', detail: 'supply-chain/dep-audit not available' })
    }

    // Stage 5: Report
    ctx.log.step(5, totalStages, 'Report')
    await mkdir(outputDir, { recursive: true })

    const durationMs = Date.now() - startTime
    const jsonReport = buildJsonReport(allFindings, repoPath, durationMs)
    const sarif = buildSarifReport(allFindings)
    const md = buildMarkdownReport(allFindings, repoPath, durationMs)

    await Promise.all([
      writeFile(join(outputDir, 'results.json'), JSON.stringify(jsonReport, null, 2)),
      writeFile(join(outputDir, 'results.sarif'), JSON.stringify(sarif, null, 2)),
      writeFile(join(outputDir, 'results.md'), md),
    ])

    const summary = buildScanSummary(allFindings, durationMs)
    stages.push({
      stage: 'Report',
      status: 'done',
      detail: `${summary.total} findings (${summary.critical}C/${summary.high}H/${summary.medium}M/${summary.low}L) → ${outputDir}`,
    })

    ctx.log.info(`Scan complete in ${(durationMs / 1000).toFixed(1)}s: ${summary.total} findings`)

    return stages
  },
})
