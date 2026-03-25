/**
 * Port scanning adapter.
 * Wraps: nmap (primary), masscan (fallback)
 * Source: pentest-network-internal, pentest-recon-attack-surface
 */

import { cli, Strategy } from '../../registry.js'
import type { ExecContext } from '../../types.js'
import { runTool, findAvailableTool } from '../_utils/tool-runner.js'
import { parseNmapOutput } from './parsers.js'

cli({
  provider: 'recon',
  name: 'port-scan',
  description: 'Scan target host for open ports and services using nmap/masscan',
  strategy: Strategy.FREE,
  args: {
    target: { type: 'string', required: true, help: 'Target IP, hostname, or CIDR range' },
    ports: { type: 'string', required: false, default: 'top-1000', help: 'Port range (e.g., "80,443", "1-65535", "top-1000")' },
    scan_type: { type: 'string', required: false, default: 'service', choices: ['quick', 'service', 'full'], help: 'Scan intensity' },
  },
  columns: ['ip', 'port', 'protocol', 'state', 'service', 'product', 'version'],
  timeout: 600,

  async func(ctx: ExecContext, args: Record<string, unknown>) {
    const target = args.target as string
    const ports = args.ports as string
    const scanType = args.scan_type as string
    const tool = await findAvailableTool(['nmap', 'masscan'])
    if (!tool) throw new Error('Install nmap or masscan to use this command.')

    if (tool === 'nmap') {
      const nmapArgs = ['-oX', '-', target]
      if (ports !== 'top-1000') nmapArgs.push('-p', ports)
      if (scanType === 'service' || scanType === 'full') nmapArgs.push('-sV')
      if (scanType === 'full') nmapArgs.push('-sC', '-O')

      const result = await runTool({ tool: 'nmap', args: nmapArgs, timeout: 600 })
      const parsed = parseNmapOutput(result.stdout)
      ctx.log.info(`Found ${parsed.length} open ports on ${target}`)
      return parsed
    }

    // masscan fallback -- outputs JSON
    const masscanArgs = [target, '--rate', '1000', '-oJ', '-']
    if (ports !== 'top-1000') {
      masscanArgs.push('-p', ports)
    } else {
      masscanArgs.push('--top-ports', '1000')
    }

    const result = await runTool({ tool: 'masscan', args: masscanArgs, timeout: 600, allowNonZero: true })
    try {
      const entries = JSON.parse(`[${result.stdout.replace(/},\s*$/, '}')}]`)
      return entries.map((e: Record<string, unknown>) => ({
        ip: (e.ip as string) ?? '',
        port: ((e.ports as Array<Record<string, unknown>>)?.[0]?.port as number) ?? 0,
        protocol: ((e.ports as Array<Record<string, unknown>>)?.[0]?.proto as string) ?? 'tcp',
        state: 'open',
        service: '',
        product: '',
        version: '',
      }))
    } catch {
      return []
    }
  },
})
