/**
 * Bandit Python SAST adapter.
 * Wraps: bandit — Python-specific security analysis.
 * Strategy: FREE — requires bandit installed locally.
 */

import { cli, Strategy } from '../../registry.js'
import type { ExecContext } from '../../types.js'
import { ToolNotFoundError } from '../../errors.js'
import { runTool, checkToolInstalled } from '../_utils/tool-runner.js'

interface BanditResult {
  readonly test_id: string
  readonly severity: string
  readonly confidence: string
  readonly filename: string
  readonly line_number: number
  readonly issue_text: string
  readonly issue_cwe: { readonly id: number }
}

interface BanditOutput {
  readonly results?: readonly BanditResult[]
}

export function parseBanditOutput(stdout: string): Record<string, unknown>[] {
  try {
    const data: BanditOutput = JSON.parse(stdout)
    const results = data.results ?? []
    return results.map((r) => ({
      test_id: r.test_id ?? '',
      severity: r.severity ?? '',
      confidence: r.confidence ?? '',
      file: r.filename ?? '',
      line: r.line_number ?? 0,
      message: r.issue_text ?? '',
      cwe: r.issue_cwe?.id != null ? String(r.issue_cwe.id) : '',
    }))
  } catch {
    return []
  }
}

cli({
  provider: 'scan',
  name: 'bandit-scan',
  description: 'Run Python-specific security analysis using Bandit',
  strategy: Strategy.FREE,
  domain: 'code-security',
  args: {
    path: { type: 'string', required: true, help: 'Path to Python project root' },
    confidence: {
      type: 'string',
      default: 'MEDIUM',
      choices: ['LOW', 'MEDIUM', 'HIGH'],
      help: 'Minimum confidence level',
    },
  },
  columns: ['test_id', 'severity', 'confidence', 'file', 'line', 'message', 'cwe'],
  timeout: 300,

  async func(ctx: ExecContext, args: Record<string, unknown>) {
    const path = args.path as string
    const confidence = (args.confidence as string) ?? 'MEDIUM'

    if (!(await checkToolInstalled('bandit'))) {
      throw new ToolNotFoundError('bandit', 'pip install bandit')
    }

    const result = await runTool({
      tool: 'bandit',
      args: ['-r', path, '-f', 'json', '--confidence', confidence],
      timeout: 300,
      allowNonZero: true,
    })

    const findings = parseBanditOutput(result.stdout)
    ctx.log.info(`bandit found ${findings.length} issues`)
    return findings
  },
})
