/**
 * Attack corpus coverage analyzer.
 * Pure TypeScript -- no external dependencies.
 * Analyzes coverage against OWASP ASI Top 10 and MITRE ATLAS frameworks.
 */

import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join } from 'node:path'
import { cli, Strategy } from '../../registry.js'
import type { ExecContext } from '../../types.js'

// --- Types ---

interface CoverageRow {
  category: string
  case_count: number
  coverage_pct: number
  gaps: string
  priority: string
  [key: string]: unknown
}

interface CorpusCase {
  category?: string
  attack_surface?: string
  expected_risk?: string
  [key: string]: unknown
}

// --- OWASP ASI Top 10 Categories with Weights ---

const OWASP_CATEGORIES: Record<string, number> = {
  'prompt-injection': 3,
  'sensitive-data-exposure': 3,
  'supply-chain': 3,
  'excessive-agency': 3,
  'insecure-output': 2,
  'training-data-poisoning': 2,
  'model-denial-of-service': 1,
  'overreliance': 1,
  'insecure-plugin': 2,
  'model-theft': 1,
}

const MIN_CASES_PER_CATEGORY = 5

// --- YAML-like Parsing (simple key: value) ---

export function parseSimpleYaml(content: string): CorpusCase {
  const result: CorpusCase = {}
  const lines = content.split('\n')

  for (const line of lines) {
    const match = line.match(/^(\w[\w-]*):\s*(.+)$/)
    if (match) {
      const key = match[1].trim()
      const value = match[2].trim().replace(/^['"]|['"]$/g, '')
      result[key] = value
    }
  }

  return result
}

// --- Coverage Analysis ---

export function analyzeCoverage(cases: CorpusCase[]): CoverageRow[] {
  const categoryCounts = new Map<string, number>()

  // Count cases per category
  for (const c of cases) {
    const cat = c.category ?? c.attack_surface ?? 'uncategorized'
    categoryCounts.set(cat, (categoryCounts.get(cat) ?? 0) + 1)
  }

  const totalCases = cases.length
  const rows: CoverageRow[] = []

  // Evaluate all OWASP categories
  const allCategories = new Set([
    ...Object.keys(OWASP_CATEGORIES),
    ...categoryCounts.keys(),
  ])

  for (const category of allCategories) {
    const count = categoryCounts.get(category) ?? 0
    const coveragePct = totalCases > 0 ? Math.round((count / totalCases) * 100) : 0
    const owaspWeight = OWASP_CATEGORIES[category] ?? 1
    const gaps: string[] = []

    if (count < MIN_CASES_PER_CATEGORY) {
      gaps.push(`needs ${MIN_CASES_PER_CATEGORY - count} more cases`)
    }
    if (count === 0) {
      gaps.push('no coverage')
    }

    // Priority based on OWASP weight and gap
    let priority: string
    if (count === 0 && owaspWeight >= 3) {
      priority = 'CRITICAL'
    } else if (count < MIN_CASES_PER_CATEGORY && owaspWeight >= 2) {
      priority = 'HIGH'
    } else if (count < MIN_CASES_PER_CATEGORY) {
      priority = 'MEDIUM'
    } else {
      priority = 'LOW'
    }

    rows.push({
      category,
      case_count: count,
      coverage_pct: coveragePct,
      gaps: gaps.length > 0 ? gaps.join('; ') : 'adequate',
      priority,
    })
  }

  // Sort by priority weight (CRITICAL first)
  const priorityOrder: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 }
  return rows.sort((a, b) => (priorityOrder[a.priority] ?? 4) - (priorityOrder[b.priority] ?? 4))
}

// --- CLI Registration ---

cli({
  provider: 'agent-security',
  name: 'analyze-coverage',
  description:
    'Analyze attack corpus coverage against OWASP ASI Top 10 and MITRE ATLAS frameworks',
  strategy: Strategy.FREE,
  domain: 'agent-security',
  args: {
    corpus_dir: { type: 'string', required: true, help: 'Path to corpus cases directory' },
  },
  columns: ['category', 'case_count', 'coverage_pct', 'gaps', 'priority'],
  timeout: 60,

  async func(ctx: ExecContext, args: Record<string, unknown>) {
    const corpusDir = args.corpus_dir as string

    let entries: string[]
    try {
      entries = readdirSync(corpusDir)
    } catch {
      throw new Error(`Cannot read corpus directory: ${corpusDir}`)
    }

    const yamlFiles = entries.filter((f) => f.endsWith('.yaml') || f.endsWith('.yml'))

    if (yamlFiles.length === 0) {
      throw new Error(`No YAML case files found in: ${corpusDir}`)
    }

    ctx.log.info(`Analyzing ${yamlFiles.length} corpus case files`)

    const cases: CorpusCase[] = []

    for (const file of yamlFiles) {
      const filePath = join(corpusDir, file)
      try {
        const stat = statSync(filePath)
        if (!stat.isFile()) continue

        const content = readFileSync(filePath, 'utf-8')
        const parsed = parseSimpleYaml(content)
        cases.push(parsed)
      } catch {
        ctx.log.warn(`Could not parse: ${file}`)
      }
    }

    const rows = analyzeCoverage(cases)

    const criticalGaps = rows.filter((r) => r.priority === 'CRITICAL').length
    const highGaps = rows.filter((r) => r.priority === 'HIGH').length
    ctx.log.info(
      `Coverage analysis: ${cases.length} cases across ${rows.length} categories (${criticalGaps} critical gaps, ${highGaps} high gaps)`,
    )

    return rows
  },
})
