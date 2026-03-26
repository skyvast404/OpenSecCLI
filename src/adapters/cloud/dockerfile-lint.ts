/**
 * Dockerfile security linting adapter.
 * Wraps: hadolint
 * Source: pentest-cloud-infrastructure
 */

import { cli, Strategy } from '../../registry.js'
import type { ExecContext } from '../../types.js'
import { runToolJson, checkToolInstalled } from '../_utils/tool-runner.js'
import { ToolNotFoundError } from '../../errors.js'

interface HadolintResult {
  level: string
  code: string
  message: string
  line: number
  column: number
  file: string
}

export function parseHadolintOutput(data: HadolintResult[]): Record<string, unknown>[] {
  return data.map((item) => ({
    rule: item.code ?? '',
    severity: mapHadolintSeverity(item.level ?? ''),
    line: item.line ?? 0,
    message: item.message ?? '',
  }))
}

function mapHadolintSeverity(level: string): string {
  const lower = level.toLowerCase()
  if (lower === 'error') return 'high'
  if (lower === 'warning') return 'medium'
  if (lower === 'info') return 'low'
  if (lower === 'style') return 'info'
  return 'info'
}

cli({
  provider: 'cloud',
  name: 'dockerfile-lint',
  description: 'Lint Dockerfiles for security best practices and CIS compliance using hadolint',
  strategy: Strategy.FREE,
  domain: 'cloud-security',
  args: {
    file: { type: 'string', required: true, help: 'Path to Dockerfile' },
  },
  columns: ['rule', 'severity', 'line', 'message'],
  timeout: 60,

  async func(ctx: ExecContext, args: Record<string, unknown>) {
    const file = args.file as string

    if (!(await checkToolInstalled('hadolint'))) {
      throw new ToolNotFoundError('hadolint', 'brew install hadolint / scoop install hadolint')
    }

    const data = await runToolJson<HadolintResult[]>({
      tool: 'hadolint',
      args: ['--format', 'json', file],
      timeout: 60,
      allowNonZero: true,
    })

    const results = parseHadolintOutput(data)
    ctx.log.info(`hadolint found ${results.length} issues in ${file}`)
    return results
  },
})
