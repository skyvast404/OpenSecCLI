/**
 * Report generator for agent security assessments.
 * Reads grading results and produces a structured Markdown report.
 * Pure TypeScript — no external tool dependencies.
 */

import { cli, Strategy } from '../../registry.js'
import type { AdapterResult, ExecContext } from '../../types.js'
import { readdir, readFile, writeFile } from 'node:fs/promises'
import { join, dirname } from 'node:path'
import { mkdir } from 'node:fs/promises'

interface GradingResult {
  case_id?: string
  category?: string
  result?: string
  score?: number
  severity?: string
  defense_effective?: boolean
  details?: string
  [key: string]: unknown
}

function buildExecutiveSummary(results: GradingResult[]): string {
  const total = results.length
  const passed = results.filter((r) => r.result === 'pass').length
  const failed = results.filter((r) => r.result === 'fail').length
  const avgScore =
    total > 0 ? results.reduce((sum, r) => sum + (r.score ?? 0), 0) / total : 0

  const lines = [
    '## Executive Summary',
    '',
    `- **Total test cases:** ${total}`,
    `- **Passed:** ${passed}`,
    `- **Failed:** ${failed}`,
    `- **Pass rate:** ${total > 0 ? ((passed / total) * 100).toFixed(1) : 0}%`,
    `- **Average score:** ${avgScore.toFixed(2)}`,
    '',
  ]

  return lines.join('\n')
}

function buildTestResultsTable(results: GradingResult[]): string {
  const lines = [
    '## Test Results',
    '',
    '| Case ID | Category | Result | Score | Severity |',
    '|---------|----------|--------|-------|----------|',
  ]

  for (const r of results) {
    lines.push(
      `| ${r.case_id ?? 'N/A'} | ${r.category ?? 'N/A'} | ${r.result ?? 'N/A'} | ${r.score ?? 'N/A'} | ${r.severity ?? 'N/A'} |`,
    )
  }

  lines.push('')
  return lines.join('\n')
}

function buildCoverageAnalysis(results: GradingResult[]): string {
  const categories = new Map<string, { total: number; passed: number }>()

  for (const r of results) {
    const cat = r.category ?? 'uncategorized'
    const entry = categories.get(cat) ?? { total: 0, passed: 0 }
    const updated = {
      total: entry.total + 1,
      passed: entry.passed + (r.result === 'pass' ? 1 : 0),
    }
    categories.set(cat, updated)
  }

  const lines = [
    '## Coverage Analysis',
    '',
    '| Category | Total | Passed | Coverage |',
    '|----------|-------|--------|----------|',
  ]

  for (const [cat, data] of categories) {
    const coverage = data.total > 0 ? ((data.passed / data.total) * 100).toFixed(1) : '0.0'
    lines.push(`| ${cat} | ${data.total} | ${data.passed} | ${coverage}% |`)
  }

  lines.push('')
  return lines.join('\n')
}

function buildDefenseEffectiveness(results: GradingResult[]): string {
  const effective = results.filter((r) => r.defense_effective === true).length
  const ineffective = results.filter((r) => r.defense_effective === false).length
  const unknown = results.filter((r) => r.defense_effective === undefined).length

  const lines = [
    '## Defense Effectiveness',
    '',
    `- **Effective defenses:** ${effective}`,
    `- **Ineffective defenses:** ${ineffective}`,
    `- **Unknown/untested:** ${unknown}`,
    '',
  ]

  if (ineffective > 0) {
    lines.push('### Cases with Ineffective Defenses', '')
    for (const r of results.filter((r) => r.defense_effective === false)) {
      lines.push(`- **${r.case_id ?? 'N/A'}**: ${r.details ?? 'No details available'}`)
    }
    lines.push('')
  }

  return lines.join('\n')
}

function buildRecommendations(results: GradingResult[]): string {
  const failed = results.filter((r) => r.result === 'fail')
  const lines = ['## Recommendations', '']

  if (failed.length === 0) {
    lines.push('All test cases passed. Continue monitoring and updating test suites.')
  } else {
    const criticalFails = failed.filter((r) => r.severity === 'critical')
    const highFails = failed.filter((r) => r.severity === 'high')

    if (criticalFails.length > 0) {
      lines.push(`1. **Critical:** Address ${criticalFails.length} critical failure(s) immediately`)
    }
    if (highFails.length > 0) {
      lines.push(`${criticalFails.length > 0 ? '2' : '1'}. **High:** Remediate ${highFails.length} high-severity failure(s)`)
    }
    lines.push(`- Review and update defense playbooks for ${failed.length} failing cases`)
    lines.push('- Re-run assessment after applying fixes')
  }

  lines.push('')
  return lines.join('\n')
}

cli({
  provider: 'agent-security',
  name: 'write-report',
  description: 'Generate agent security assessment report from grading results',
  strategy: Strategy.FREE,
  domain: 'agent-security',
  args: {
    results_dir: {
      type: 'string',
      required: true,
      help: 'Path to grading results directory',
    },
    output: {
      type: 'string',
      required: true,
      help: 'Output report file path',
    },
  },
  columns: ['section', 'content_preview'],

  async func(ctx: ExecContext, args: Record<string, unknown>): Promise<AdapterResult> {
    const resultsDir = args.results_dir as string
    const outputPath = args.output as string

    ctx.log.info(`Generating report from ${resultsDir}`)

    let files: string[]
    try {
      files = await readdir(resultsDir)
    } catch (error) {
      throw new Error(`Cannot read results directory: ${(error as Error).message}`)
    }

    const jsonFiles = files.filter((f) => f.endsWith('.json'))
    const allResults: GradingResult[] = []

    for (const file of jsonFiles) {
      const raw = await readFile(join(resultsDir, file), 'utf-8')
      const parsed = JSON.parse(raw) as GradingResult | GradingResult[]
      if (Array.isArray(parsed)) {
        allResults.push(...parsed)
      } else {
        allResults.push(parsed)
      }
    }

    ctx.log.info(`Loaded ${allResults.length} grading results from ${jsonFiles.length} files`)

    const sections = [
      { name: 'Executive Summary', builder: buildExecutiveSummary },
      { name: 'Test Results', builder: buildTestResultsTable },
      { name: 'Coverage Analysis', builder: buildCoverageAnalysis },
      { name: 'Defense Effectiveness', builder: buildDefenseEffectiveness },
      { name: 'Recommendations', builder: buildRecommendations },
    ]

    const reportParts = ['# Agent Security Assessment Report', '']
    const sectionPreviews: Record<string, unknown>[] = []

    for (const section of sections) {
      const content = section.builder(allResults)
      reportParts.push(content)

      const preview = content.split('\n').find((l) => l.trim().length > 0 && !l.startsWith('#'))
      sectionPreviews.push({
        section: section.name,
        content_preview: (preview ?? '').trim().slice(0, 80),
      })
    }

    const report = reportParts.join('\n')

    const outputDir = dirname(outputPath)
    await mkdir(outputDir, { recursive: true })
    await writeFile(outputPath, report)

    ctx.log.info(`Report written to ${outputPath}`)
    return sectionPreviews
  },
})
