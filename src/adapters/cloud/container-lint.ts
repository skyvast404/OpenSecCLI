/**
 * Container image CIS Docker Benchmark linting adapter.
 * Wraps: dockle
 */

import { cli, Strategy } from '../../registry.js'
import type { ExecContext } from '../../types.js'
import { runExternalTool } from '../_utils/tool-runner.js'

interface DockleDetail {
  code: string
  level: string
  title: string
  alerts: string[]
}

interface DockleOutput {
  details: DockleDetail[]
}

function mapDockleLevel(level: string): string {
  const upper = level.toUpperCase()
  if (upper === 'FATAL' || upper === 'WARN') return 'high'
  if (upper === 'INFO') return 'medium'
  if (upper === 'SKIP') return 'info'
  return 'info'
}

export function parseDockleOutput(stdout: string): Record<string, unknown>[] {
  try {
    const data = JSON.parse(stdout) as DockleOutput
    return (data.details ?? []).map((d) => ({
      code: d.code ?? '',
      level: mapDockleLevel(d.level ?? ''),
      title: d.title ?? '',
      alerts: (d.alerts ?? []).join('; '),
    }))
  } catch {
    return []
  }
}

cli({
  provider: 'cloud',
  name: 'container-lint',
  description: 'Lint container images for CIS Docker Benchmark compliance using dockle',
  strategy: Strategy.FREE,
  domain: 'cloud-security',
  args: {
    image: { type: 'string', required: true, help: 'Container image to lint (e.g., nginx:latest)' },
  },
  columns: ['code', 'level', 'title', 'alerts'],
  timeout: 120,

  async func(ctx: ExecContext, args: Record<string, unknown>) {
    const image = args.image as string

    const { results } = await runExternalTool({
      tools: ['dockle'],
      buildArgs: () => ['-f', 'json', image],
      installHint: 'brew install goodwithtech/r/dockle',
      parseOutput: (stdout) => parseDockleOutput(stdout),
      allowNonZero: true,
      timeout: 120,
    })

    ctx.log.info(`Dockle found ${results.length} issues in ${image}`)
    return results
  },
})
