/**
 * Ultra-fast port scanning adapter.
 * Wraps: rustscan
 */

import { cli, Strategy } from '../../registry.js'
import type { ExecContext } from '../../types.js'
import { runExternalTool } from '../_utils/tool-runner.js'

export function parseRustscanOutput(stdout: string): Record<string, unknown>[] {
  const results: Record<string, unknown>[] = []
  const lines = stdout.split('\n')

  for (const line of lines) {
    const trimmed = line.trim()
    if (!trimmed) continue

    // Greppable format: <ip> -> [<port1>,<port2>,...]
    const match = trimmed.match(/^([\d.]+)\s*->\s*\[([^\]]*)\]/)
    if (match) {
      const ip = match[1]
      const portsStr = match[2]
      const ports = portsStr
        .split(',')
        .map((p) => p.trim())
        .filter((p) => p.length > 0)

      for (const port of ports) {
        results.push({
          ip,
          port: parseInt(port, 10),
          protocol: 'tcp',
          status: 'open',
        })
      }
    }
  }

  return results
}

cli({
  provider: 'recon',
  name: 'fast-scan',
  description: 'Ultra-fast port scanning (65535 ports in seconds) using rustscan',
  strategy: Strategy.FREE,
  domain: 'recon',
  args: {
    target: { type: 'string', required: true, help: 'Target IP or hostname' },
    top_ports: { type: 'number', required: false, help: 'Only scan top N ports' },
  },
  columns: ['ip', 'port', 'protocol', 'status'],
  timeout: 120,

  async func(ctx: ExecContext, args: Record<string, unknown>) {
    const target = args.target as string
    const topPorts = args.top_ports as number | undefined

    const { results } = await runExternalTool({
      tools: ['rustscan'],
      buildArgs: () => {
        const a = ['-a', target, '--ulimit', '5000', '-g']
        if (topPorts) {
          a.push('--top', String(topPorts))
        }
        return a
      },
      installHint: 'cargo install rustscan / brew install rustscan',
      parseOutput: (stdout) => parseRustscanOutput(stdout),
      allowNonZero: true,
      timeout: 120,
    })

    ctx.log.info(`rustscan found ${results.length} open ports on ${target}`)
    return results
  },
})
