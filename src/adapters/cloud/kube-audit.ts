/**
 * Kubernetes security auditing adapter.
 * Wraps: kube-bench (primary), kube-hunter (fallback)
 * Source: pentest-cloud-infrastructure
 */

import { cli, Strategy } from '../../registry.js'
import type { ExecContext } from '../../types.js'
import { runExternalTool } from '../_utils/tool-runner.js'

interface KubeBenchResult {
  test_number: string
  test_desc: string
  status: string
  remediation?: string
  severity?: string
}

interface KubeBenchTest {
  results?: KubeBenchResult[]
}

interface KubeBenchControl {
  tests?: KubeBenchTest[]
}

interface KubeBenchOutput {
  Controls?: KubeBenchControl[]
}

interface KubeHunterVulnerability {
  vid: string
  description: string
  severity: string
  category?: string
  evidence?: string
}

interface KubeHunterOutput {
  vulnerabilities?: KubeHunterVulnerability[]
}

export function parseKubeBenchOutput(stdout: string): Record<string, unknown>[] {
  try {
    const data = JSON.parse(stdout) as KubeBenchOutput
    const rows: Record<string, unknown>[] = []
    for (const control of data.Controls ?? []) {
      for (const test of control.tests ?? []) {
        for (const result of test.results ?? []) {
          if (result.status === 'FAIL' || result.status === 'WARN') {
            rows.push({
              id: result.test_number,
              description: result.test_desc,
              status: result.status,
              severity: result.severity ?? (result.status === 'FAIL' ? 'HIGH' : 'MEDIUM'),
              remediation: result.remediation ?? '',
            })
          }
        }
      }
    }
    return rows
  } catch {
    return []
  }
}

export function parseKubeHunterOutput(stdout: string): Record<string, unknown>[] {
  try {
    const data = JSON.parse(stdout) as KubeHunterOutput
    return (data.vulnerabilities ?? []).map((v) => ({
      id: v.vid,
      description: v.description,
      status: 'FAIL',
      severity: v.severity?.toUpperCase() ?? 'MEDIUM',
      remediation: v.evidence ?? '',
    }))
  } catch {
    return []
  }
}

function parseOutput(stdout: string, tool: string): Record<string, unknown>[] {
  if (tool === 'kube-bench') {
    return parseKubeBenchOutput(stdout)
  }
  return parseKubeHunterOutput(stdout)
}

cli({
  provider: 'cloud',
  name: 'kube-audit',
  description: 'Audit Kubernetes cluster security using kube-bench/kube-hunter',
  strategy: Strategy.FREE,
  args: {
    target: {
      type: 'string',
      required: false,
      default: 'node',
      choices: ['node', 'master', 'controlplane', 'policies'],
      help: 'Audit target type',
    },
  },
  columns: ['id', 'description', 'status', 'severity', 'remediation'],
  timeout: 300,

  async func(ctx: ExecContext, args: Record<string, unknown>) {
    const target = (args.target as string) ?? 'node'

    const { results } = await runExternalTool({
      tools: ['kube-bench', 'kube-hunter'],
      buildArgs: (tool) => {
        if (tool === 'kube-bench') {
          return ['run', '--targets', target, '--json']
        }
        // kube-hunter
        return ['--json', '--active']
      },
      parseOutput,
      allowNonZero: true,
      timeout: 300,
    })

    ctx.log.info(`Kubernetes audit found ${results.length} issues (target: ${target})`)
    return results
  },
})
