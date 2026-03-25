/**
 * Report generator adapter for OpenSecCLI scan results.
 * Produces JSON, SARIF 2.1.0, and Markdown reports from RawFinding arrays.
 */

import { cli, Strategy } from '../../registry.js'
import type { AdapterResult, ExecContext } from '../../types.js'
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

interface SarifRun {
  tool: {
    driver: {
      name: string
      version: string
      rules: Array<{
        id: string
        shortDescription: { text: string }
        properties: Record<string, unknown>
      }>
    }
  }
  results: Array<{
    ruleId: string
    level: string
    message: { text: string }
    locations: Array<{
      physicalLocation: {
        artifactLocation: { uri: string }
        region: { startLine: number }
      }
    }>
    properties: Record<string, unknown>
  }>
}

interface SarifReport {
  $schema: string
  version: string
  runs: SarifRun[]
}

export function buildSarifReport(findings: RawFinding[]): SarifReport {
  const rules = findings.map(f => ({
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

  async func(ctx: ExecContext, args: Record<string, unknown>): Promise<AdapterResult> {
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
