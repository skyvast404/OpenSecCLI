/**
 * Infrastructure-as-Code scanning adapter.
 * Wraps: checkov (primary), terrascan (fallback)
 * Source: pentest-cloud-infrastructure
 */

import { cli, Strategy } from '../../registry.js'
import type { ExecContext } from '../../types.js'
import { runExternalTool } from '../_utils/tool-runner.js'

interface CheckovFailedCheck {
  check_id: string
  resource: string
  check_result: { result: string }
  guideline?: string
  file_path?: string
  severity?: string
}

interface CheckovOutput {
  results?: {
    failed_checks?: CheckovFailedCheck[]
  }
}

interface TerrascanViolation {
  rule_id: string
  resource_name: string
  severity: string
  description: string
  file?: string
}

interface TerrascanOutput {
  results?: {
    violations?: TerrascanViolation[]
  }
}

export function parseCheckovOutput(stdout: string): Record<string, unknown>[] {
  try {
    const data = JSON.parse(stdout) as CheckovOutput
    const checks = data.results?.failed_checks ?? []
    return checks.map((c) => ({
      check_id: c.check_id,
      resource: c.resource,
      severity: c.severity ?? 'MEDIUM',
      status: c.check_result?.result ?? 'FAILED',
      detail: c.guideline ?? '',
      file: c.file_path ?? '',
    }))
  } catch {
    return []
  }
}

export function parseTerrascanOutput(stdout: string): Record<string, unknown>[] {
  try {
    const data = JSON.parse(stdout) as TerrascanOutput
    const violations = data.results?.violations ?? []
    return violations.map((v) => ({
      check_id: v.rule_id,
      resource: v.resource_name,
      severity: v.severity,
      status: 'FAILED',
      detail: v.description,
      file: v.file ?? '',
    }))
  } catch {
    return []
  }
}

function parseOutput(stdout: string, tool: string): Record<string, unknown>[] {
  if (tool === 'checkov') {
    return parseCheckovOutput(stdout)
  }
  return parseTerrascanOutput(stdout)
}

cli({
  provider: 'cloud',
  name: 'iac-scan',
  description: 'Scan Infrastructure-as-Code files for misconfigurations using checkov/terrascan',
  strategy: Strategy.FREE,
  domain: 'cloud-security',
  args: {
    path: { type: 'string', required: true, help: 'Path to IaC files or directory' },
    framework: {
      type: 'string',
      required: false,
      choices: ['terraform', 'cloudformation', 'kubernetes', 'dockerfile'],
      help: 'IaC framework type (auto-detected if omitted)',
    },
  },
  columns: ['check_id', 'resource', 'severity', 'status', 'detail', 'file'],
  timeout: 300,

  async func(ctx: ExecContext, args: Record<string, unknown>) {
    const path = args.path as string
    const framework = args.framework as string | undefined

    const { results } = await runExternalTool({
      tools: ['checkov', 'terrascan'],
      buildArgs: (tool) => {
        if (tool === 'checkov') {
          const a = ['-d', path, '-o', 'json', '--quiet', '--compact']
          if (framework) a.push('--framework', framework)
          return a
        }
        // terrascan
        const a = ['scan', '-d', path, '-o', 'json']
        if (framework) a.push('-t', framework)
        return a
      },
      parseOutput,
      allowNonZero: true,
      timeout: 300,
    })

    ctx.log.info(`IaC scan found ${results.length} issues in ${path}`)
    return results
  },
})
