/**
 * Gosec Go SAST adapter.
 * Wraps: gosec — Go-specific security analysis.
 * Strategy: FREE — requires gosec installed locally.
 */

import { cli, Strategy } from '../../registry.js'
import type { ExecContext } from '../../types.js'
import { ToolNotFoundError } from '../../errors.js'
import { runTool, checkToolInstalled } from '../_utils/tool-runner.js'

interface GosecIssue {
  readonly severity: string
  readonly confidence: string
  readonly cwe: { readonly id: string }
  readonly rule_id: string
  readonly details: string
  readonly file: string
  readonly line: string
  readonly column: string
}

interface GosecOutput {
  readonly Issues?: readonly GosecIssue[]
}

export function parseGosecOutput(stdout: string): Record<string, unknown>[] {
  try {
    const data: GosecOutput = JSON.parse(stdout)
    const issues = data.Issues ?? []
    return issues.map((issue) => ({
      rule_id: issue.rule_id ?? '',
      severity: issue.severity ?? '',
      confidence: issue.confidence ?? '',
      file: issue.file ?? '',
      line: issue.line ?? '',
      message: issue.details ?? '',
      cwe: issue.cwe?.id ?? '',
    }))
  } catch {
    return []
  }
}

cli({
  provider: 'scan',
  name: 'gosec-scan',
  description: 'Run Go-specific security analysis using gosec',
  strategy: Strategy.FREE,
  domain: 'code-security',
  args: {
    path: { type: 'string', required: true, help: 'Path to Go project root' },
  },
  columns: ['rule_id', 'severity', 'confidence', 'file', 'line', 'message', 'cwe'],
  timeout: 300,

  async func(ctx: ExecContext, args: Record<string, unknown>) {
    const path = args.path as string

    if (!(await checkToolInstalled('gosec'))) {
      throw new ToolNotFoundError(
        'gosec',
        'go install github.com/securego/gosec/v2/cmd/gosec@latest',
      )
    }

    const result = await runTool({
      tool: 'gosec',
      args: ['-fmt', 'json', './...'],
      cwd: path,
      timeout: 300,
      allowNonZero: true,
    })

    const findings = parseGosecOutput(result.stdout)
    ctx.log.info(`gosec found ${findings.length} issues`)
    return findings
  },
})
