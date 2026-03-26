/**
 * Snyk vulnerability scanner adapter.
 * Wraps: snyk CLI (deps, container, IaC, SAST)
 * Source: pentest-supply-chain
 */

import { cli, Strategy } from '../../registry.js'
import type { ExecContext } from '../../types.js'
import { ToolNotFoundError } from '../../errors.js'
import { runTool, checkToolInstalled } from '../_utils/tool-runner.js'

interface SnykVuln {
  packageName?: string
  version?: string
  severity?: string
  title?: string
  fixedIn?: string[]
  exploit?: string
}

interface SnykTestOutput {
  vulnerabilities?: SnykVuln[]
}

interface SnykIacIssue {
  id?: string
  severity?: string
  title?: string
  resolve?: string
  path?: string[]
}

interface SnykIacOutput {
  infrastructureAsCodeIssues?: SnykIacIssue[]
}

/**
 * Parse Snyk test JSON output (deps, container, code scans).
 */
export function parseSnykTestOutput(raw: string): Record<string, unknown>[] {
  const data = JSON.parse(raw) as SnykTestOutput
  const vulns = data.vulnerabilities ?? []
  return vulns.map((v) => ({
    package: v.packageName ?? '',
    version: v.version ?? '',
    severity: (v.severity ?? 'medium').toLowerCase(),
    vulnerability: v.title ?? '',
    fix_version: v.fixedIn?.[0] ?? 'N/A',
    exploit_maturity: v.exploit ?? 'unknown',
  }))
}

/**
 * Parse Snyk IaC test JSON output.
 */
export function parseSnykIacOutput(raw: string): Record<string, unknown>[] {
  const data = JSON.parse(raw) as SnykIacOutput
  const issues = data.infrastructureAsCodeIssues ?? []
  return issues.map((issue) => ({
    package: issue.id ?? '',
    version: '',
    severity: (issue.severity ?? 'medium').toLowerCase(),
    vulnerability: issue.title ?? '',
    fix_version: issue.resolve ?? 'N/A',
    exploit_maturity: (issue.path ?? []).join(' > '),
  }))
}

cli({
  provider: 'supply-chain',
  name: 'snyk-scan',
  description: 'Scan dependencies, containers, and IaC for vulnerabilities using Snyk',
  strategy: Strategy.API_KEY,
  auth: 'snyk',
  domain: 'supply-chain',
  args: {
    path: { type: 'string', required: true, help: 'Project path, container image, or IaC directory' },
    scan_type: {
      type: 'string',
      default: 'deps',
      choices: ['deps', 'container', 'iac', 'code'],
      help: 'Scan type',
    },
  },
  columns: ['package', 'version', 'severity', 'vulnerability', 'fix_version', 'exploit_maturity'],
  timeout: 300,

  async func(ctx: ExecContext, args: Record<string, unknown>) {
    const path = args.path as string
    const scanType = (args.scan_type as string) ?? 'deps'

    if (!(await checkToolInstalled('snyk'))) {
      throw new ToolNotFoundError('snyk', 'npm install -g snyk && snyk auth')
    }

    const buildSnykArgs = (): string[] => {
      switch (scanType) {
        case 'container':
          return ['container', 'test', path, '--json']
        case 'iac':
          return ['iac', 'test', path, '--json']
        case 'code':
          return ['code', 'test', path, '--json']
        default:
          return ['test', '--json', path]
      }
    }

    const result = await runTool({
      tool: 'snyk',
      args: buildSnykArgs(),
      timeout: 300,
      allowNonZero: true,
      env: { SNYK_TOKEN: ctx.auth?.api_key ?? '' },
    })

    const findings = scanType === 'iac'
      ? parseSnykIacOutput(result.stdout)
      : parseSnykTestOutput(result.stdout)

    ctx.log.info(`Snyk found ${findings.length} issues (${scanType} scan)`)
    return findings
  },
})
