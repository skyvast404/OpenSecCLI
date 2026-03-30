/**
 * Autopilot — one command to scan everything.
 * opensec autopilot https://target.com
 * opensec autopilot --path ./myproject
 */

import { existsSync } from 'node:fs'
import { mkdir, writeFile } from 'node:fs/promises'
import { resolve } from 'node:path'
import chalk from 'chalk'
import { getRegistry } from '../registry.js'
import { executeCommand } from '../execution.js'
import { checkToolInstalled } from '../adapters/_utils/tool-runner.js'
import { upsertFinding, recordScan } from '../db/store.js'

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type TargetType = 'url' | 'path'
export type ScanDepth = 'quick' | 'standard' | 'deep'

interface AutopilotOptions {
  readonly depth: ScanDepth
  readonly output: string
}

interface StepDefinition {
  readonly label: string
  readonly commandId: string
  readonly args: Record<string, unknown>
  readonly requiredTool?: string
  readonly minDepth: ScanDepth
}

interface StepResult {
  readonly label: string
  readonly commandId: string
  readonly status: 'completed' | 'skipped' | 'failed'
  readonly skipReason?: string
  readonly error?: string
  readonly findings: readonly Finding[]
  readonly durationMs: number
}

interface Finding {
  readonly severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  readonly source: string
  readonly title: string
  readonly detail?: string
  readonly [key: string]: unknown
}

interface AutopilotReport {
  readonly target: string
  readonly targetType: TargetType
  readonly depth: ScanDepth
  readonly startedAt: string
  readonly finishedAt: string
  readonly durationMs: number
  readonly grade: string
  readonly score: number
  readonly steps: readonly StepResult[]
  readonly findings: readonly Finding[]
  readonly summary: {
    readonly total: number
    readonly critical: number
    readonly high: number
    readonly medium: number
    readonly low: number
    readonly info: number
  }
  readonly stepsCompleted: number
  readonly stepsSkipped: number
  readonly stepsTotal: number
  readonly skippedReasons: readonly string[]
}

// ---------------------------------------------------------------------------
// Depth ordering for minDepth check
// ---------------------------------------------------------------------------

const DEPTH_ORDER: Record<ScanDepth, number> = {
  quick: 0,
  standard: 1,
  deep: 2,
}

function meetsDepth(required: ScanDepth, current: ScanDepth): boolean {
  return DEPTH_ORDER[current] >= DEPTH_ORDER[required]
}

// ---------------------------------------------------------------------------
// Target type detection
// ---------------------------------------------------------------------------

export function detectTargetType(target: string): TargetType {
  if (/^https?:\/\//i.test(target)) {
    return 'url'
  }
  if (/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//i.test(target)) {
    return 'url'
  }
  // Bare domain-like strings (contains dot, no slashes at start, no spaces)
  if (/^[a-zA-Z0-9]([a-zA-Z0-9-]*\.)+[a-zA-Z]{2,}(\/.*)?$/.test(target)) {
    return 'url'
  }
  return 'path'
}

// ---------------------------------------------------------------------------
// Extract domain from URL
// ---------------------------------------------------------------------------

function extractDomain(url: string): string {
  try {
    const parsed = new URL(url.startsWith('http') ? url : `https://${url}`)
    return parsed.hostname
  } catch {
    return url.replace(/^https?:\/\//, '').split('/')[0]
  }
}

// ---------------------------------------------------------------------------
// Step definitions
// ---------------------------------------------------------------------------

function buildUrlSteps(target: string): readonly StepDefinition[] {
  const domain = extractDomain(target)
  const url = target.startsWith('http') ? target : `https://${target}`

  return [
    {
      label: 'Header Audit',
      commandId: 'vuln/header-audit',
      args: { url },
      minDepth: 'quick',
    },
    {
      label: 'CORS Check',
      commandId: 'vuln/cors-check',
      args: { url },
      minDepth: 'quick',
    },
    {
      label: 'Certificate Transparency',
      commandId: 'crtsh/cert-search',
      args: { domain },
      minDepth: 'quick',
    },
    {
      label: 'Tech Fingerprint',
      commandId: 'recon/tech-fingerprint',
      args: { target: url },
      requiredTool: 'httpx',
      minDepth: 'quick',
    },
    {
      label: 'Nuclei Vulnerability Scan',
      commandId: 'vuln/nuclei-scan',
      args: { target: url },
      requiredTool: 'nuclei',
      minDepth: 'standard',
    },
    {
      label: 'XSS Scan',
      commandId: 'vuln/xss-scan',
      args: { url },
      requiredTool: 'dalfox',
      minDepth: 'deep',
    },
    {
      label: 'Domain Enrichment',
      commandId: 'enrichment/domain-enrich',
      args: { domain },
      minDepth: 'quick',
    },
  ]
}

function buildPathSteps(target: string): readonly StepDefinition[] {
  const resolvedPath = resolve(target)

  return [
    {
      label: 'SAST Analysis',
      commandId: 'scan/analyze',
      args: { path: resolvedPath },
      minDepth: 'quick',
    },
    {
      label: 'Dependency Audit',
      commandId: 'supply-chain/dep-audit',
      args: { path: resolvedPath },
      minDepth: 'quick',
    },
    {
      label: 'CI/CD Config Audit',
      commandId: 'supply-chain/ci-audit',
      args: { path: resolvedPath },
      minDepth: 'quick',
    },
    {
      label: 'Secret Scanning',
      commandId: 'secrets/trufflehog-scan',
      args: { path: resolvedPath },
      requiredTool: 'trufflehog',
      minDepth: 'standard',
    },
    {
      label: 'Project Discovery',
      commandId: 'scan/discover',
      args: { path: resolvedPath },
      minDepth: 'quick',
    },
    {
      label: 'Entry Point Enumeration',
      commandId: 'scan/entrypoints',
      args: { path: resolvedPath },
      minDepth: 'quick',
    },
  ]
}

// ---------------------------------------------------------------------------
// Step execution
// ---------------------------------------------------------------------------

async function executeStep(step: StepDefinition): Promise<StepResult> {
  const start = Date.now()

  // Check if command exists in registry
  const registry = getRegistry()
  if (!registry.has(step.commandId)) {
    return {
      label: step.label,
      commandId: step.commandId,
      status: 'skipped',
      skipReason: `command ${step.commandId} not registered`,
      findings: [],
      durationMs: Date.now() - start,
    }
  }

  // Check required external tool
  if (step.requiredTool) {
    const installed = await checkToolInstalled(step.requiredTool)
    if (!installed) {
      return {
        label: step.label,
        commandId: step.commandId,
        status: 'skipped',
        skipReason: `${step.requiredTool} not installed`,
        findings: [],
        durationMs: Date.now() - start,
      }
    }
  }

  try {
    // Capture stdout by temporarily replacing process.stdout.write
    const outputChunks: string[] = []
    const originalWrite = process.stdout.write.bind(process.stdout)
    process.stdout.write = (chunk: string | Uint8Array): boolean => {
      outputChunks.push(typeof chunk === 'string' ? chunk : Buffer.from(chunk).toString())
      return true
    }

    try {
      await executeCommand(step.commandId, step.args, { format: 'json' })
    } finally {
      process.stdout.write = originalWrite
    }

    const rawOutput = outputChunks.join('')
    const findings = parseFindings(rawOutput, step.label)

    return {
      label: step.label,
      commandId: step.commandId,
      status: 'completed',
      findings,
      durationMs: Date.now() - start,
    }
  } catch (error) {
    return {
      label: step.label,
      commandId: step.commandId,
      status: 'failed',
      error: (error as Error).message,
      findings: [],
      durationMs: Date.now() - start,
    }
  }
}

// ---------------------------------------------------------------------------
// Finding extraction from JSON output
// ---------------------------------------------------------------------------

function parseFindings(rawOutput: string, source: string): readonly Finding[] {
  try {
    const data = JSON.parse(rawOutput.trim())
    const rows: Record<string, unknown>[] = Array.isArray(data) ? data : [data]

    return rows.map(row => ({
      severity: normalizeSeverity(row),
      source,
      title: extractTitle(row),
      detail: typeof row['detail'] === 'string' ? row['detail'] : undefined,
      ...row,
    }))
  } catch {
    // Not valid JSON — no findings to extract
    return []
  }
}

function normalizeSeverity(row: Record<string, unknown>): Finding['severity'] {
  const raw = String(
    row['severity'] ?? row['risk'] ?? row['level'] ?? row['criticality'] ?? 'info',
  ).toLowerCase()

  if (raw.includes('critical') || raw.includes('crit')) return 'critical'
  if (raw.includes('high') || raw === 'error') return 'high'
  if (raw.includes('medium') || raw.includes('med') || raw === 'warning') return 'medium'
  if (raw.includes('low')) return 'low'
  return 'info'
}

function extractTitle(row: Record<string, unknown>): string {
  for (const key of ['title', 'name', 'rule_id', 'rule', 'header', 'issue', 'message', 'description']) {
    if (typeof row[key] === 'string' && row[key]) {
      return row[key] as string
    }
  }
  return 'Finding'
}

// ---------------------------------------------------------------------------
// Scoring
// ---------------------------------------------------------------------------

function computeScore(findings: readonly Finding[]): number {
  let score = 100

  for (const f of findings) {
    switch (f.severity) {
      case 'critical':
        score -= 15
        break
      case 'high':
        score -= 8
        break
      case 'medium':
        score -= 4
        break
      case 'low':
        score -= 1
        break
      // info: no penalty
    }
  }

  return Math.max(0, Math.min(100, score))
}

function scoreToGrade(score: number): string {
  if (score >= 90) return 'A'
  if (score >= 80) return 'B'
  if (score >= 70) return 'C'
  if (score >= 60) return 'D'
  return 'F'
}

// ---------------------------------------------------------------------------
// Progress output
// ---------------------------------------------------------------------------

function writeProgress(index: number, total: number, label: string): void {
  process.stderr.write(chalk.cyan(`  [${index}/${total}]`) + ` ${label}...\n`)
}

function writeStepResult(index: number, total: number, result: StepResult): void {
  const prefix = `  [${index}/${total}]`
  const duration = `(${(result.durationMs / 1000).toFixed(1)}s)`

  switch (result.status) {
    case 'completed':
      process.stderr.write(
        chalk.green(`${prefix} ✓ ${result.label}`) +
        chalk.gray(` ${duration} — ${result.findings.length} finding(s)\n`),
      )
      break
    case 'skipped':
      process.stderr.write(
        chalk.yellow(`${prefix} - ${result.label}`) +
        chalk.gray(` skipped: ${result.skipReason}\n`),
      )
      break
    case 'failed':
      process.stderr.write(
        chalk.red(`${prefix} ✗ ${result.label}`) +
        chalk.gray(` ${duration} — ${result.error}\n`),
      )
      break
  }
}

// ---------------------------------------------------------------------------
// Report rendering
// ---------------------------------------------------------------------------

function renderReport(report: AutopilotReport): void {
  const w = (s: string) => process.stderr.write(s)
  const line = '═'.repeat(43)
  const thin = '─'.repeat(43)

  w('\n')
  w(chalk.bold(`  ${line}\n`))
  w(chalk.bold('   OpenSecCLI Autopilot Report\n'))
  w(chalk.bold(`  ${line}\n`))
  w(`   Target: ${report.target}\n`)
  w(`   Depth:  ${report.depth}\n`)
  w(`   Grade:  ${report.grade} (${report.score}/100)\n`)
  w(`  ${thin}\n`)
  w(`   Findings: ${report.summary.total} total\n`)
  w(`     Critical: ${report.summary.critical}\n`)
  w(`     High:     ${report.summary.high}\n`)
  w(`     Medium:   ${report.summary.medium}\n`)
  w(`     Low:      ${report.summary.low}\n`)
  if (report.summary.info > 0) {
    w(`     Info:     ${report.summary.info}\n`)
  }
  w(`  ${thin}\n`)
  w(`   Steps completed: ${report.stepsCompleted}/${report.stepsTotal}\n`)

  if (report.stepsSkipped > 0) {
    const reasons = report.skippedReasons.join(', ')
    w(`   Steps skipped:   ${report.stepsSkipped} (${reasons})\n`)
  }

  w(`   Duration:        ${(report.durationMs / 1000).toFixed(1)}s\n`)
  w(chalk.bold(`  ${line}\n`))
  w('\n')
}

// ---------------------------------------------------------------------------
// Main entry point
// ---------------------------------------------------------------------------

export async function runAutopilot(
  target: string,
  opts: AutopilotOptions,
): Promise<AutopilotReport> {
  const depth = opts.depth
  const outputDir = resolve(opts.output)
  const targetType = detectTargetType(target)
  const startedAt = new Date()

  process.stderr.write('\n')
  process.stderr.write(chalk.bold('  OpenSecCLI Autopilot\n'))
  process.stderr.write(chalk.gray(`  Target: ${target} (${targetType})\n`))
  process.stderr.write(chalk.gray(`  Depth:  ${depth}\n`))
  process.stderr.write('\n')

  // Build step list based on target type and depth
  const allSteps = targetType === 'url'
    ? buildUrlSteps(target)
    : buildPathSteps(target)

  const steps = allSteps.filter(s => meetsDepth(s.minDepth, depth))
  const totalSteps = steps.length

  // Execute steps — parallel where safe, with progress output
  // We run steps sequentially for clear progress reporting and
  // to avoid overwhelming external tools
  const results: StepResult[] = []

  for (let i = 0; i < steps.length; i++) {
    writeProgress(i + 1, totalSteps, steps[i].label)
    const result = await executeStep(steps[i])
    writeStepResult(i + 1, totalSteps, result)
    results.push(result)
  }

  // Aggregate findings
  const allFindings = results.flatMap(r => r.findings)

  // Persist findings to DB (best-effort)
  try {
    for (const f of allFindings) {
      upsertFinding(target, {
        source: f.source,
        severity: f.severity,
        title: f.title,
        detail: f.detail,
        raw: f,
      })
    }
    const totalDuration = results.reduce((sum, r) => sum + r.durationMs, 0)
    recordScan(target, 'autopilot', allFindings.length, totalDuration)
  } catch {
    // DB save is best-effort — don't break autopilot
  }

  const score = computeScore(allFindings)
  const grade = scoreToGrade(score)

  const summary = {
    total: allFindings.length,
    critical: allFindings.filter(f => f.severity === 'critical').length,
    high: allFindings.filter(f => f.severity === 'high').length,
    medium: allFindings.filter(f => f.severity === 'medium').length,
    low: allFindings.filter(f => f.severity === 'low').length,
    info: allFindings.filter(f => f.severity === 'info').length,
  }

  const completedSteps = results.filter(r => r.status === 'completed')
  const skippedSteps = results.filter(r => r.status === 'skipped')
  const skippedReasons = skippedSteps.map(s => s.skipReason ?? 'unknown')

  const finishedAt = new Date()
  const durationMs = finishedAt.getTime() - startedAt.getTime()

  const report: AutopilotReport = {
    target,
    targetType,
    depth,
    startedAt: startedAt.toISOString(),
    finishedAt: finishedAt.toISOString(),
    durationMs,
    grade,
    score,
    steps: results,
    findings: allFindings,
    summary,
    stepsCompleted: completedSteps.length,
    stepsSkipped: skippedSteps.length,
    stepsTotal: totalSteps,
    skippedReasons,
  }

  // Render summary to stderr
  renderReport(report)

  // Save JSON report
  try {
    await mkdir(outputDir, { recursive: true })
    const reportPath = resolve(outputDir, 'autopilot-report.json')
    await writeFile(reportPath, JSON.stringify(report, null, 2), 'utf-8')
    process.stderr.write(chalk.gray(`  Report saved: ${reportPath}\n\n`))
  } catch (error) {
    process.stderr.write(chalk.yellow(`  Could not save report: ${(error as Error).message}\n\n`))
  }

  // Output findings as JSON to stdout for piping
  process.stdout.write(JSON.stringify(report, null, 2) + '\n')

  return report
}
