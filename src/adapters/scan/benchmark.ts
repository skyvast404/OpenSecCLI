/**
 * Benchmark runner adapter for OpenSecCLI.
 * Deterministic orchestrator for measuring detection quality (precision/recall/F1).
 * Inspired by damocles_sword's secscan-benchmark.
 */

import { cli, Strategy, getRegistry } from '../../registry.js'
import type { AdapterResult, ExecContext } from '../../types.js'
import { readFile, mkdir, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { tmpdir } from 'node:os'

// --- Types ---

export interface BenchmarkCase {
  id: string
  path: string
  truth_cwes: string[]
}

export interface BenchmarkSuite {
  name: string
  cases: BenchmarkCase[]
}

export interface BenchmarkManifest {
  suites: BenchmarkSuite[]
}

export interface SuiteResult {
  suite: string
  cases_total: number
  tp: number
  fp: number
  fn: number
  precision: number
  recall: number
  f1: number
}

// --- CWE Equivalence Map ---

const CWE_EQUIVALENCE_PAIRS: ReadonlyArray<readonly [string, string]> = [
  ['CWE-94', 'CWE-96'],
  ['CWE-94', 'CWE-95'],
  ['CWE-863', 'CWE-639'],
  ['CWE-345', 'CWE-347'],
  ['CWE-915', 'CWE-1321'],
  ['CWE-190', 'CWE-682'],
  ['CWE-338', 'CWE-330'],
  ['CWE-943', 'CWE-89'],
  ['CWE-256', 'CWE-287'],
  ['CWE-665', 'CWE-628'],
] as const

function buildEquivalenceIndex(): ReadonlyMap<string, ReadonlySet<string>> {
  const index = new Map<string, Set<string>>()

  for (const [a, b] of CWE_EQUIVALENCE_PAIRS) {
    if (!index.has(a)) index.set(a, new Set([a]))
    if (!index.has(b)) index.set(b, new Set([b]))
    index.get(a)!.add(b)
    index.get(b)!.add(a)
  }

  return index
}

const EQUIVALENCE_INDEX = buildEquivalenceIndex()

// --- CWE Normalization ---

/**
 * Normalize a CWE identifier: uppercase, strip leading zeros.
 * e.g. "cwe-089" → "CWE-89", "CWE-79" → "CWE-79"
 */
export function normalizeCwe(raw: string): string {
  const upper = raw.toUpperCase().trim()
  const match = upper.match(/^CWE-0*(\d+)$/)
  if (!match) return upper
  return `CWE-${match[1]}`
}

// --- Glob Pattern Matching ---

/**
 * Simple glob pattern matcher supporting * and ? wildcards.
 */
function matchGlob(pattern: string, value: string): boolean {
  if (pattern === '*') return true

  const escaped = pattern
    .replace(/[.+^${}()|[\]\\]/g, '\\$&')
    .replace(/\*/g, '.*')
    .replace(/\?/g, '.')

  return new RegExp(`^${escaped}$`).test(value)
}

// --- Scoring ---

export interface ScoreResult {
  tp: number
  fp: number
  fn: number
}

/**
 * Strict scoring: exact CWE match only.
 */
export function scoreStrict(predicted: readonly string[], truth: readonly string[]): ScoreResult {
  const predSet = new Set(predicted.map(normalizeCwe))
  const truthSet = new Set(truth.map(normalizeCwe))

  let tp = 0
  for (const cwe of predSet) {
    if (truthSet.has(cwe)) {
      tp += 1
    }
  }

  return {
    tp,
    fp: predSet.size - tp,
    fn: truthSet.size - tp,
  }
}

/**
 * Check if two CWEs are equivalent under the loose equivalence map.
 */
function cweMatchesLoose(predicted: string, truth: string): boolean {
  if (predicted === truth) return true
  const equivalents = EQUIVALENCE_INDEX.get(predicted)
  return equivalents !== undefined && equivalents.has(truth)
}

/**
 * Loose scoring: CWE equivalence map applied.
 */
export function scoreLoose(predicted: readonly string[], truth: readonly string[]): ScoreResult {
  const predNorm = predicted.map(normalizeCwe)
  const truthNorm = truth.map(normalizeCwe)

  const matchedTruth = new Set<number>()
  const matchedPred = new Set<number>()

  for (let pi = 0; pi < predNorm.length; pi++) {
    for (let ti = 0; ti < truthNorm.length; ti++) {
      if (!matchedTruth.has(ti) && !matchedPred.has(pi) && cweMatchesLoose(predNorm[pi], truthNorm[ti])) {
        matchedPred.add(pi)
        matchedTruth.add(ti)
      }
    }
  }

  return {
    tp: matchedPred.size,
    fp: predNorm.length - matchedPred.size,
    fn: truthNorm.length - matchedTruth.size,
  }
}

/**
 * Calculate precision, recall, and F1 from TP/FP/FN counts.
 */
export function calcMetrics(tp: number, fp: number, fn: number): { precision: number; recall: number; f1: number } {
  const precision = tp + fp > 0 ? tp / (tp + fp) : 0
  const recall = tp + fn > 0 ? tp / (tp + fn) : 0
  const f1 = precision + recall > 0 ? (2 * precision * recall) / (precision + recall) : 0

  return {
    precision: Math.round(precision * 10000) / 10000,
    recall: Math.round(recall * 10000) / 10000,
    f1: Math.round(f1 * 10000) / 10000,
  }
}

// --- Suite Runner ---

async function runCase(
  ctx: ExecContext,
  benchCase: BenchmarkCase,
  timeout: number,
): Promise<string[]> {
  const scanCmd = getRegistry().get('scan/full')
  if (!scanCmd?.func) {
    ctx.log.warn('scan/full adapter not found in registry')
    return []
  }

  const tempDir = join(tmpdir(), `opensec-bench-${benchCase.id}-${Date.now()}`)
  await mkdir(tempDir, { recursive: true })

  try {
    const result = await Promise.race([
      scanCmd.func(ctx, {
        path: benchCase.path,
        output_dir: tempDir,
        format: 'json',
      }),
      new Promise<never>((_, reject) =>
        setTimeout(() => reject(new Error(`Timeout after ${timeout}s`)), timeout * 1000),
      ),
    ])

    const rows = Array.isArray(result) ? result : [result]
    const cwes: string[] = []

    for (const row of rows) {
      const cwe = row.cwe as string | undefined
      if (cwe && typeof cwe === 'string' && cwe.length > 0) {
        cwes.push(normalizeCwe(cwe))
      }
    }

    return [...new Set(cwes)]
  } catch (error) {
    ctx.log.warn(`Case ${benchCase.id} failed: ${(error as Error).message}`)
    return []
  }
}

function aggregateSuite(
  suite: BenchmarkSuite,
  caseResults: ReadonlyMap<string, string[]>,
  scoringMode: string,
): SuiteResult {
  let totalTp = 0
  let totalFp = 0
  let totalFn = 0

  for (const benchCase of suite.cases) {
    const predicted = caseResults.get(benchCase.id) ?? []
    const truth = benchCase.truth_cwes

    const scoreFn = scoringMode === 'loose' ? scoreLoose : scoreStrict
    const score = scoreFn(predicted, truth)

    totalTp += score.tp
    totalFp += score.fp
    totalFn += score.fn
  }

  const metrics = calcMetrics(totalTp, totalFp, totalFn)

  return {
    suite: suite.name,
    cases_total: suite.cases.length,
    tp: totalTp,
    fp: totalFp,
    fn: totalFn,
    ...metrics,
  }
}

// --- CLI Registration ---

cli({
  provider: 'scan',
  name: 'benchmark',
  description: 'Run security scanner benchmarks and measure detection quality (precision/recall/F1)',
  strategy: Strategy.FREE,
  domain: 'code-security',
  args: {
    manifest: { type: 'string', required: true, help: 'Path to benchmark manifest JSON file' },
    suite_filter: { type: 'string', required: false, default: '*', help: 'Glob pattern to filter suites' },
    timeout: { type: 'number', required: false, default: 300, help: 'Timeout per case in seconds' },
    scoring: {
      type: 'string',
      required: false,
      default: 'both',
      choices: ['strict', 'loose', 'both'],
      help: 'CWE scoring mode',
    },
    output_dir: { type: 'string', required: false, default: './benchmark-results', help: 'Output directory' },
  },
  columns: ['suite', 'cases_total', 'tp', 'fp', 'fn', 'precision', 'recall', 'f1'],
  timeout: 3600,

  async func(ctx: ExecContext, args: Record<string, unknown>): Promise<AdapterResult> {
    const manifestPath = args.manifest as string
    const suiteFilter = (args.suite_filter as string) ?? '*'
    const timeoutSec = (args.timeout as number) ?? 300
    const scoring = (args.scoring as string) ?? 'both'
    const outputDir = (args.output_dir as string) ?? './benchmark-results'

    // Load manifest
    const raw = await readFile(manifestPath, 'utf-8')
    const manifest: BenchmarkManifest = JSON.parse(raw)

    // Filter suites by glob
    const suites = manifest.suites.filter((s) => matchGlob(suiteFilter, s.name))

    if (suites.length === 0) {
      ctx.log.warn(`No suites matched filter "${suiteFilter}"`)
      return []
    }

    ctx.log.info(`Running ${suites.length} suite(s) with ${scoring} scoring`)

    const allResults: SuiteResult[] = []

    for (const [suiteIdx, suite] of suites.entries()) {
      ctx.log.step(suiteIdx + 1, suites.length, suite.name)

      const caseResults = new Map<string, string[]>()

      for (const benchCase of suite.cases) {
        ctx.log.verbose(`  Case: ${benchCase.id}`)
        const predicted = await runCase(ctx, benchCase, timeoutSec)
        caseResults.set(benchCase.id, predicted)
      }

      if (scoring === 'both') {
        const strictResult = aggregateSuite(suite, caseResults, 'strict')
        allResults.push({ ...strictResult, suite: `${suite.name} (strict)` })
        const looseResult = aggregateSuite(suite, caseResults, 'loose')
        allResults.push({ ...looseResult, suite: `${suite.name} (loose)` })
      } else {
        const result = aggregateSuite(suite, caseResults, scoring)
        allResults.push(result)
      }
    }

    // Write results
    await mkdir(outputDir, { recursive: true })
    await writeFile(
      join(outputDir, 'benchmark-results.json'),
      JSON.stringify(allResults, null, 2),
    )

    ctx.log.info(`Results written to ${outputDir}/benchmark-results.json`)

    return allResults.map((r) => ({ ...r } as Record<string, unknown>))
  },
})
