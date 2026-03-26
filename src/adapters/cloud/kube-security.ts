/**
 * Kubernetes security scanning adapter.
 * Wraps: kubescape
 * Source: pentest-cloud-infrastructure
 */

import { cli, Strategy } from '../../registry.js'
import type { ExecContext } from '../../types.js'
import { runTool, checkToolInstalled } from '../_utils/tool-runner.js'
import { ToolNotFoundError } from '../../errors.js'

interface KubescapeControl {
  controlID: string
  name: string
  severity?: { scoreFactor?: number }
  status?: { status?: string }
  rules?: Array<{
    name?: string
    status?: string
  }>
}

interface KubescapeResourceResult {
  resourceID?: string
  controls?: KubescapeControl[]
}

interface KubescapeOutput {
  results?: KubescapeResourceResult[]
  summaryDetails?: {
    frameworks?: Array<{ name?: string }>
  }
}

export function parseKubescapeOutput(stdout: string): Record<string, unknown>[] {
  try {
    const data = JSON.parse(stdout) as KubescapeOutput
    const rows: Record<string, unknown>[] = []
    const frameworkName = data.summaryDetails?.frameworks?.[0]?.name ?? ''

    for (const result of data.results ?? []) {
      const resource = result.resourceID ?? ''
      for (const control of result.controls ?? []) {
        const status = control.status?.status ?? 'unknown'
        rows.push({
          control_id: control.controlID ?? '',
          control_name: control.name ?? '',
          severity: mapKubescapeSeverity(control.severity?.scoreFactor),
          status,
          resource,
          framework: frameworkName,
        })
      }
    }
    return rows
  } catch {
    return []
  }
}

function mapKubescapeSeverity(scoreFactor?: number): string {
  if (scoreFactor == null) return 'medium'
  if (scoreFactor >= 9) return 'critical'
  if (scoreFactor >= 7) return 'high'
  if (scoreFactor >= 4) return 'medium'
  return 'low'
}

cli({
  provider: 'cloud',
  name: 'kube-security',
  description: 'Scan Kubernetes clusters and manifests for security issues using kubescape (NSA/CISA/MITRE)',
  strategy: Strategy.FREE,
  domain: 'cloud-security',
  args: {
    target: {
      type: 'string',
      required: false,
      help: 'Path to manifest file or directory (default: current cluster)',
    },
    framework: {
      type: 'string',
      required: false,
      default: 'nsa',
      choices: ['nsa', 'mitre', 'cis-v1.23', 'all-controls'],
      help: 'Security framework',
    },
  },
  columns: ['control_id', 'control_name', 'severity', 'status', 'resource', 'framework'],
  timeout: 300,

  async func(ctx: ExecContext, args: Record<string, unknown>) {
    const target = args.target as string | undefined
    const framework = (args.framework as string) ?? 'nsa'

    if (!(await checkToolInstalled('kubescape'))) {
      throw new ToolNotFoundError(
        'kubescape',
        'curl -s https://raw.githubusercontent.com/kubescape/kubescape/master/install.sh | /bin/bash',
      )
    }

    const kubescapeArgs = ['scan', 'framework', framework, '--format', 'json', '--output', '/dev/stdout']
    if (target) kubescapeArgs.push(target)

    const result = await runTool({
      tool: 'kubescape',
      args: kubescapeArgs,
      timeout: 300,
      allowNonZero: true,
    })

    const results = parseKubescapeOutput(result.stdout)
    ctx.log.info(`kubescape found ${results.length} controls (framework: ${framework})`)
    return results
  },
})
