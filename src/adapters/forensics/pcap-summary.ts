/**
 * PCAP network capture summary adapter.
 * Wraps: tshark
 * Source: pentest-ctf-forensics
 *
 * Performs three analyses:
 * 1. Protocol hierarchy (io,phs)
 * 2. DNS queries
 * 3. IP conversations
 */

import { cli, Strategy } from '../../registry.js'
import type { ExecContext } from '../../types.js'
import { runTool, findAvailableTool } from '../_utils/tool-runner.js'

export function parseProtocolHierarchy(stdout: string): Record<string, unknown>[] {
  const lines = stdout.split('\n').filter((l) => l.trim().length > 0)
  const rows: Record<string, unknown>[] = []

  for (const line of lines) {
    // Format: "protocol  frames:N  bytes:N"
    const parts = line.trim().split(/\s{2,}/)
    if (parts.length >= 2) {
      const protocol = parts[0].replace(/^[|`\-\s]+/, '').trim()
      if (protocol && !protocol.startsWith('Filter')) {
        rows.push({
          category: 'protocol',
          key: protocol,
          value: parts.slice(1).join(' '),
          count: '',
        })
      }
    }
  }

  return rows
}

export function parseDnsQueries(stdout: string): Record<string, unknown>[] {
  const lines = stdout.split('\n').filter((l) => l.trim().length > 0)
  const domainCounts = new Map<string, number>()

  for (const line of lines) {
    const domain = line.trim()
    if (domain && domain !== 'dns.qry.name') {
      domainCounts.set(domain, (domainCounts.get(domain) ?? 0) + 1)
    }
  }

  return [...domainCounts.entries()]
    .sort((a, b) => b[1] - a[1])
    .map(([domain, count]) => ({
      category: 'dns',
      key: domain,
      value: 'DNS query',
      count: String(count),
    }))
}

export function parseConversations(stdout: string): Record<string, unknown>[] {
  const lines = stdout.split('\n').filter((l) => l.trim().length > 0)
  const rows: Record<string, unknown>[] = []

  for (const line of lines) {
    // Skip header lines
    if (line.includes('<->') || line.includes('|')) {
      // "addr_a <-> addr_b  frames_a  bytes_a  frames_b  bytes_b  frames  bytes  start  duration"
      const parts = line.trim().split(/\s+/)
      if (parts.length >= 3) {
        const addrA = parts[0]
        // find <-> separator
        const sepIdx = parts.indexOf('<->')
        if (sepIdx >= 0 && parts.length > sepIdx + 1) {
          const addrB = parts[sepIdx + 1]
          const totalFrames = parts[sepIdx + 6] ?? ''
          rows.push({
            category: 'conversation',
            key: `${addrA} <-> ${addrB}`,
            value: 'IP conversation',
            count: totalFrames,
          })
        }
      }
    }
  }

  return rows
}

cli({
  provider: 'forensics',
  name: 'pcap-summary',
  description: 'Summarize PCAP network capture: protocol hierarchy, DNS queries, IP conversations',
  strategy: Strategy.FREE,
  domain: 'forensics',
  args: {
    file: { type: 'string', required: true, help: 'Path to PCAP file' },
    filter: { type: 'string', required: false, help: 'Display filter (tshark syntax)' },
  },
  columns: ['category', 'key', 'value', 'count'],
  timeout: 120,

  async func(ctx: ExecContext, args: Record<string, unknown>) {
    const filePath = args.file as string
    const displayFilter = args.filter as string | undefined

    const tool = await findAvailableTool(['tshark'])
    if (!tool) {
      throw new Error(
        'tshark is not installed. Install Wireshark/tshark to use this command.',
      )
    }

    const baseArgs = ['-r', filePath, '-q']
    if (displayFilter) {
      baseArgs.push('-Y', displayFilter)
    }

    ctx.log.info('Running PCAP analysis...')

    // Run all three analyses in parallel
    const [phsResult, dnsResult, convResult] = await Promise.allSettled([
      // 1. Protocol hierarchy
      runTool({
        tool: 'tshark',
        args: [...baseArgs, '-z', 'io,phs'],
        allowNonZero: true,
      }),
      // 2. DNS queries
      runTool({
        tool: 'tshark',
        args: ['-r', filePath, '-T', 'fields', '-e', 'dns.qry.name', '-Y', 'dns.qry.name'],
        allowNonZero: true,
      }),
      // 3. IP conversations
      runTool({
        tool: 'tshark',
        args: [...baseArgs, '-z', 'conv,ip'],
        allowNonZero: true,
      }),
    ])

    const rows: Record<string, unknown>[] = []

    if (phsResult.status === 'fulfilled') {
      rows.push(...parseProtocolHierarchy(phsResult.value.stdout))
    } else {
      ctx.log.warn('Protocol hierarchy analysis failed')
    }

    if (dnsResult.status === 'fulfilled') {
      rows.push(...parseDnsQueries(dnsResult.value.stdout))
    } else {
      ctx.log.warn('DNS query analysis failed')
    }

    if (convResult.status === 'fulfilled') {
      rows.push(...parseConversations(convResult.value.stdout))
    } else {
      ctx.log.warn('IP conversation analysis failed')
    }

    ctx.log.info(`PCAP summary: ${rows.length} items from ${filePath}`)
    return rows
  },
})
