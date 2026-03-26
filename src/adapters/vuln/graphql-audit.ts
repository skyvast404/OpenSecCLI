/**
 * GraphQL security audit adapter.
 * Wraps: graphql-cop — GraphQL API security testing.
 * Strategy: FREE — requires graphql-cop installed locally.
 */

import { cli, Strategy } from '../../registry.js'
import type { ExecContext } from '../../types.js'
import { ToolNotFoundError } from '../../errors.js'
import { runTool, checkToolInstalled } from '../_utils/tool-runner.js'

interface GraphqlCopFinding {
  readonly title: string
  readonly severity: string
  readonly description: string
  readonly impact: string
}

export function parseGraphqlCopOutput(stdout: string): Record<string, unknown>[] {
  try {
    const data: readonly GraphqlCopFinding[] = JSON.parse(stdout)
    if (!Array.isArray(data)) return []
    return data.map((finding) => ({
      title: finding.title ?? '',
      severity: finding.severity ?? '',
      description: finding.description ?? '',
      impact: finding.impact ?? '',
    }))
  } catch {
    return []
  }
}

cli({
  provider: 'vuln',
  name: 'graphql-audit',
  description: 'Audit GraphQL API for security issues using graphql-cop',
  strategy: Strategy.FREE,
  domain: 'vuln-scan',
  args: {
    url: { type: 'string', required: true, help: 'GraphQL endpoint URL' },
  },
  columns: ['title', 'severity', 'description', 'impact'],
  timeout: 120,

  async func(ctx: ExecContext, args: Record<string, unknown>) {
    const url = args.url as string

    if (!(await checkToolInstalled('graphql-cop'))) {
      throw new ToolNotFoundError('graphql-cop', 'pip install graphql-cop')
    }

    const result = await runTool({
      tool: 'graphql-cop',
      args: ['-t', url, '-o', 'json'],
      timeout: 120,
      allowNonZero: true,
    })

    const findings = parseGraphqlCopOutput(result.stdout)
    ctx.log.info(`graphql-cop found ${findings.length} issues`)
    return findings
  },
})
