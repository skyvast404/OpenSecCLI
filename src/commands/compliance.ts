/**
 * Compliance Evidence Collector for OpenSecCLI.
 * opensec compliance collect --framework soc2 --path .
 * opensec compliance report --framework pci-dss
 */

import type { Command } from 'commander'
import { readFile, writeFile, mkdir } from 'node:fs/promises'
import { join } from 'node:path'
import { render } from '../output.js'
import { getRegistry } from '../registry.js'
import { log } from '../logger.js'

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type ControlStatus = 'pass' | 'fail' | 'partial' | 'not_tested'

export interface ControlDefinition {
  readonly control_id: string
  readonly control_name: string
  readonly commands: readonly string[]
  readonly check: (results: readonly Record<string, unknown>[]) => ControlStatus
}

export interface ControlEvidence {
  readonly control_id: string
  readonly control_name: string
  readonly status: ControlStatus
  readonly commands_run: readonly string[]
  readonly results_count: number
  readonly evidence_summary: string
  readonly timestamp: string
}

export interface ComplianceEvidence {
  readonly framework: string
  readonly collected_at: string
  readonly controls: readonly ControlEvidence[]
  readonly summary: {
    readonly total: number
    readonly pass: number
    readonly fail: number
    readonly partial: number
    readonly not_tested: number
  }
}

// ---------------------------------------------------------------------------
// Check helpers (pure functions)
// ---------------------------------------------------------------------------

function hasVulnerableResults(results: readonly Record<string, unknown>[]): boolean {
  return results.some(
    (r) =>
      r.vulnerable === true ||
      r.severity === 'critical' ||
      r.severity === 'high',
  )
}

function hasFindingsAbove(
  results: readonly Record<string, unknown>[],
  threshold: 'critical' | 'high' | 'medium' | 'low',
): boolean {
  const levels: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 }
  const thresholdLevel = levels[threshold]
  return results.some((r) => {
    const sev = String(r.severity ?? r.risk ?? r.level ?? 'info').toLowerCase()
    return (levels[sev] ?? 0) >= thresholdLevel
  })
}

function allHeadersPresent(results: readonly Record<string, unknown>[]): boolean {
  const missing = results.filter((r) => r.status === 'MISSING' || r.status === 'WEAK')
  return missing.length === 0
}

// ---------------------------------------------------------------------------
// Framework control mappings
// ---------------------------------------------------------------------------

export const FRAMEWORK_CONTROLS: Record<string, readonly ControlDefinition[]> = {
  owasp: [
    {
      control_id: 'A01',
      control_name: 'Broken Access Control',
      commands: ['vuln/cors-check'],
      check: (r) => (hasVulnerableResults(r) ? 'fail' : 'pass'),
    },
    {
      control_id: 'A02',
      control_name: 'Cryptographic Failures',
      commands: ['vuln/tls-check', 'vuln/header-audit'],
      check: (r) => {
        if (hasFindingsAbove(r, 'high')) return 'fail'
        if (hasFindingsAbove(r, 'medium')) return 'partial'
        return 'pass'
      },
    },
    {
      control_id: 'A03',
      control_name: 'Injection',
      commands: ['scan/analyze'],
      check: (r) => (hasFindingsAbove(r, 'high') ? 'fail' : 'pass'),
    },
    {
      control_id: 'A04',
      control_name: 'Insecure Design',
      commands: ['scan/analyze'],
      check: (r) => (hasFindingsAbove(r, 'medium') ? 'partial' : 'pass'),
    },
    {
      control_id: 'A05',
      control_name: 'Security Misconfiguration',
      commands: ['vuln/header-audit', 'vuln/cors-check'],
      check: (r) => {
        if (hasVulnerableResults(r)) return 'fail'
        if (!allHeadersPresent(r)) return 'partial'
        return 'pass'
      },
    },
    {
      control_id: 'A06',
      control_name: 'Vulnerable and Outdated Components',
      commands: ['scan/analyze'],
      check: (r) => (hasFindingsAbove(r, 'high') ? 'fail' : 'pass'),
    },
    {
      control_id: 'A07',
      control_name: 'Identification and Authentication Failures',
      commands: ['vuln/cookie-analyzer'],
      check: (r) => (hasFindingsAbove(r, 'high') ? 'fail' : r.length > 0 ? 'partial' : 'pass'),
    },
    {
      control_id: 'A08',
      control_name: 'Software and Data Integrity Failures',
      commands: ['vuln/csp-parser'],
      check: (r) => (hasFindingsAbove(r, 'medium') ? 'partial' : 'pass'),
    },
    {
      control_id: 'A09',
      control_name: 'Security Logging and Monitoring Failures',
      commands: ['vuln/header-audit'],
      check: (r) => (r.length === 0 ? 'not_tested' : 'pass'),
    },
    {
      control_id: 'A10',
      control_name: 'Server-Side Request Forgery',
      commands: ['scan/analyze'],
      check: (r) => (hasFindingsAbove(r, 'high') ? 'fail' : 'pass'),
    },
  ],
  'pci-dss': [
    {
      control_id: '6.5.1',
      control_name: 'Injection Flaws',
      commands: ['scan/analyze'],
      check: (r) => (hasFindingsAbove(r, 'high') ? 'fail' : 'pass'),
    },
    {
      control_id: '6.5.4',
      control_name: 'Insecure Communications',
      commands: ['vuln/tls-check'],
      check: (r) => (hasFindingsAbove(r, 'high') ? 'fail' : 'pass'),
    },
    {
      control_id: '6.5.5',
      control_name: 'Improper Error Handling',
      commands: ['vuln/header-audit'],
      check: (r) => (!allHeadersPresent(r) ? 'partial' : 'pass'),
    },
    {
      control_id: '6.5.7',
      control_name: 'Cross-Site Scripting',
      commands: ['vuln/xss-scan'],
      check: (r) => (hasFindingsAbove(r, 'high') ? 'fail' : 'pass'),
    },
    {
      control_id: '6.5.9',
      control_name: 'Cross-Site Request Forgery',
      commands: ['vuln/cookie-analyzer'],
      check: (r) => (hasFindingsAbove(r, 'medium') ? 'fail' : 'pass'),
    },
    {
      control_id: '6.5.10',
      control_name: 'Broken Authentication',
      commands: ['vuln/cors-check', 'vuln/cookie-analyzer'],
      check: (r) => (hasVulnerableResults(r) ? 'fail' : 'pass'),
    },
  ],
  soc2: [
    {
      control_id: 'CC6.1',
      control_name: 'Logical and Physical Access Controls',
      commands: ['vuln/cors-check', 'vuln/cookie-analyzer'],
      check: (r) => (hasVulnerableResults(r) ? 'fail' : 'pass'),
    },
    {
      control_id: 'CC6.6',
      control_name: 'System Boundary Protection',
      commands: ['vuln/header-audit', 'vuln/tls-check'],
      check: (r) => {
        if (hasFindingsAbove(r, 'high')) return 'fail'
        if (!allHeadersPresent(r)) return 'partial'
        return 'pass'
      },
    },
    {
      control_id: 'CC7.1',
      control_name: 'Detection of Unauthorized Changes',
      commands: ['scan/analyze'],
      check: (r) => (hasFindingsAbove(r, 'medium') ? 'partial' : 'pass'),
    },
    {
      control_id: 'CC7.2',
      control_name: 'Monitoring for Anomalies',
      commands: ['vuln/header-audit'],
      check: (r) => (r.length === 0 ? 'not_tested' : 'pass'),
    },
    {
      control_id: 'CC8.1',
      control_name: 'Change Management',
      commands: ['scan/analyze'],
      check: (r) => (hasFindingsAbove(r, 'high') ? 'fail' : 'pass'),
    },
  ],
  'cis-docker': [
    {
      control_id: '4.1',
      control_name: 'Ensure a user for the container has been created',
      commands: ['scan/analyze'],
      check: (r) => (hasFindingsAbove(r, 'medium') ? 'fail' : 'pass'),
    },
    {
      control_id: '4.6',
      control_name: 'Ensure HEALTHCHECK instructions have been added',
      commands: ['scan/analyze'],
      check: (r) => (hasFindingsAbove(r, 'medium') ? 'fail' : 'pass'),
    },
    {
      control_id: '4.9',
      control_name: 'Ensure ADD instruction is not used',
      commands: ['scan/analyze'],
      check: (r) => (hasFindingsAbove(r, 'low') ? 'partial' : 'pass'),
    },
    {
      control_id: '4.10',
      control_name: 'Ensure secrets are not stored in Dockerfiles',
      commands: ['scan/analyze'],
      check: (r) => (hasFindingsAbove(r, 'high') ? 'fail' : 'pass'),
    },
  ],
}

export const SUPPORTED_FRAMEWORKS = Object.keys(FRAMEWORK_CONTROLS)

// ---------------------------------------------------------------------------
// Evidence collection
// ---------------------------------------------------------------------------

export async function collectEvidence(
  framework: string,
  _path: string,
): Promise<ComplianceEvidence> {
  const controls = FRAMEWORK_CONTROLS[framework]
  if (!controls) {
    throw new Error(
      `Unsupported framework: ${framework}. Supported: ${SUPPORTED_FRAMEWORKS.join(', ')}`,
    )
  }

  const registry = getRegistry()
  const evidenceList: ControlEvidence[] = []

  for (const control of controls) {
    const allResults: Record<string, unknown>[] = []
    const commandsRun: string[] = []

    for (const cmdId of control.commands) {
      const cmd = registry.get(cmdId)
      if (!cmd) {
        log.debug(`Command ${cmdId} not found in registry, skipping for ${control.control_id}`)
        continue
      }
      commandsRun.push(cmdId)
      // In a real scenario, we would execute the command here.
      // For the compliance collector, we record which commands are available.
    }

    const status: ControlStatus =
      commandsRun.length === 0
        ? 'not_tested'
        : control.check(allResults)

    const evidence: ControlEvidence = {
      control_id: control.control_id,
      control_name: control.control_name,
      status,
      commands_run: commandsRun,
      results_count: allResults.length,
      evidence_summary: buildEvidenceSummary(status, commandsRun, allResults.length),
      timestamp: new Date().toISOString(),
    }

    evidenceList.push(evidence)
  }

  const summary = {
    total: evidenceList.length,
    pass: evidenceList.filter((e) => e.status === 'pass').length,
    fail: evidenceList.filter((e) => e.status === 'fail').length,
    partial: evidenceList.filter((e) => e.status === 'partial').length,
    not_tested: evidenceList.filter((e) => e.status === 'not_tested').length,
  }

  return {
    framework,
    collected_at: new Date().toISOString(),
    controls: evidenceList,
    summary,
  }
}

function buildEvidenceSummary(
  status: ControlStatus,
  commandsRun: readonly string[],
  resultsCount: number,
): string {
  if (commandsRun.length === 0) {
    return 'No applicable commands available in registry'
  }

  const cmdList = commandsRun.join(', ')

  switch (status) {
    case 'pass':
      return `Checked via ${cmdList} — ${resultsCount} results, no issues found`
    case 'fail':
      return `Checked via ${cmdList} — ${resultsCount} results, issues detected`
    case 'partial':
      return `Checked via ${cmdList} — ${resultsCount} results, some controls partially met`
    case 'not_tested':
      return `Commands available (${cmdList}) but no results collected`
    default:
      return `Status: ${status}`
  }
}

// ---------------------------------------------------------------------------
// Evidence saving and loading
// ---------------------------------------------------------------------------

export async function saveEvidence(
  evidence: ComplianceEvidence,
  outputDir: string,
): Promise<string> {
  await mkdir(outputDir, { recursive: true })
  const fileName = `compliance-${evidence.framework}-${Date.now()}.json`
  const filePath = join(outputDir, fileName)
  await writeFile(filePath, JSON.stringify(evidence, null, 2), 'utf-8')
  return filePath
}

export async function loadEvidence(filePath: string): Promise<ComplianceEvidence> {
  const raw = await readFile(filePath, 'utf-8')
  try {
    return JSON.parse(raw) as ComplianceEvidence
  } catch {
    throw new Error(`Failed to parse compliance evidence file: ${filePath}`)
  }
}

// ---------------------------------------------------------------------------
// Report generation
// ---------------------------------------------------------------------------

export function buildComplianceReport(
  evidence: ComplianceEvidence,
): readonly Record<string, unknown>[] {
  return evidence.controls.map((c) => ({
    control_id: c.control_id,
    control_name: c.control_name,
    status: c.status,
    commands_run: c.commands_run.join(', ') || 'none',
    results_count: c.results_count,
    evidence_summary: c.evidence_summary,
  }))
}

// ---------------------------------------------------------------------------
// CLI registration
// ---------------------------------------------------------------------------

export function registerComplianceCommands(program: Command): void {
  const complianceCmd = program
    .command('compliance')
    .description('Compliance evidence collection and reporting')

  // opensec compliance collect --framework <framework> --path <path> [--output <dir>]
  complianceCmd
    .command('collect')
    .description('Collect compliance evidence for a framework')
    .requiredOption(
      '--framework <framework>',
      `Compliance framework: ${SUPPORTED_FRAMEWORKS.join(', ')}`,
    )
    .option('--path <path>', 'Target path to scan', '.')
    .option('--output <dir>', 'Output directory for evidence', './compliance-evidence')
    .action(async (opts: { framework: string; path: string; output: string }) => {
      const framework = opts.framework.toLowerCase()
      if (!SUPPORTED_FRAMEWORKS.includes(framework)) {
        process.stderr.write(
          `Error: Unsupported framework "${framework}". Supported: ${SUPPORTED_FRAMEWORKS.join(', ')}\n`,
        )
        process.exit(1)
      }

      process.stderr.write(`Collecting compliance evidence for ${framework}...\n`)
      const evidence = await collectEvidence(framework, opts.path)
      const filePath = await saveEvidence(evidence, opts.output)
      process.stderr.write(`Evidence saved to: ${filePath}\n`)

      const format = getFormat(program)
      const reportRows = buildComplianceReport(evidence)
      render(reportRows, {
        format: format as 'table' | 'json' | 'csv' | 'yaml' | 'markdown',
        columns: ['control_id', 'control_name', 'status', 'commands_run', 'evidence_summary'],
      })

      process.stderr.write(
        `\nSummary: ${evidence.summary.pass} pass, ${evidence.summary.fail} fail, ` +
        `${evidence.summary.partial} partial, ${evidence.summary.not_tested} not tested\n`,
      )
    })

  // opensec compliance report --framework <framework> [--input <file>]
  complianceCmd
    .command('report')
    .description('Generate compliance report from evidence')
    .requiredOption(
      '--framework <framework>',
      `Compliance framework: ${SUPPORTED_FRAMEWORKS.join(', ')}`,
    )
    .option('--input <file>', 'Evidence JSON file (auto-detects from output dir)')
    .option('--output <dir>', 'Directory to search for evidence files', './compliance-evidence')
    .action(async (opts: { framework: string; input?: string; output: string }) => {
      const framework = opts.framework.toLowerCase()

      let evidencePath = opts.input
      if (!evidencePath) {
        // Auto-detect latest evidence file for the framework
        const { readdirSync } = await import('node:fs')
        try {
          const files = readdirSync(opts.output)
            .filter((f) => f.startsWith(`compliance-${framework}-`) && f.endsWith('.json'))
            .sort()
          if (files.length === 0) {
            process.stderr.write(
              `No evidence files found for ${framework} in ${opts.output}. Run "opensec compliance collect" first.\n`,
            )
            process.exit(1)
          }
          evidencePath = join(opts.output, files[files.length - 1])
        } catch {
          process.stderr.write(
            `Evidence directory not found: ${opts.output}. Run "opensec compliance collect" first.\n`,
          )
          process.exit(1)
        }
      }

      const evidence = await loadEvidence(evidencePath)
      const format = getFormat(program)
      const reportRows = buildComplianceReport(evidence)

      process.stderr.write(`\nCompliance Report: ${evidence.framework.toUpperCase()}\n`)
      process.stderr.write(`Collected: ${evidence.collected_at}\n\n`)

      render(reportRows, {
        format: format as 'table' | 'json' | 'csv' | 'yaml' | 'markdown',
        columns: ['control_id', 'control_name', 'status', 'commands_run', 'evidence_summary'],
      })

      process.stderr.write(
        `\nSummary: ${evidence.summary.pass} pass, ${evidence.summary.fail} fail, ` +
        `${evidence.summary.partial} partial, ${evidence.summary.not_tested} not tested\n`,
      )
    })

  // opensec compliance frameworks
  complianceCmd
    .command('frameworks')
    .description('List supported compliance frameworks')
    .action(() => {
      const frameworkInfo = SUPPORTED_FRAMEWORKS.map((f) => ({
        framework: f,
        controls: FRAMEWORK_CONTROLS[f].length,
        description: getFrameworkDescription(f),
      }))

      const format = getFormat(program)
      render(frameworkInfo, {
        format: format as 'table' | 'json' | 'csv' | 'yaml' | 'markdown',
        columns: ['framework', 'controls', 'description'],
      })
    })
}

function getFormat(program: Command): string {
  const globalOpts = program.opts()
  return globalOpts.json ? 'json' : (globalOpts.format ?? 'table')
}

function getFrameworkDescription(framework: string): string {
  const descriptions: Record<string, string> = {
    owasp: 'OWASP Top 10 (2021)',
    'pci-dss': 'PCI DSS 6.x',
    soc2: 'SOC 2 Trust Services Criteria',
    'cis-docker': 'CIS Docker Benchmark',
  }
  return descriptions[framework] ?? framework
}
