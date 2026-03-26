/**
 * OSINT harvester adapter.
 * Wraps: theHarvester
 * Source: pentest-osint-recon
 */

import { cli, Strategy } from '../../registry.js'
import type { ExecContext } from '../../types.js'
import { ToolNotFoundError } from '../../errors.js'
import { runTool, checkToolInstalled } from '../_utils/tool-runner.js'
import { randomBytes } from 'node:crypto'
import { readFile, unlink } from 'node:fs/promises'

interface HarvesterOutput {
  emails?: string[]
  hosts?: string[]
  ips?: string[]
  asns?: string[]
}

/**
 * Parse theHarvester JSON output into table rows.
 */
export function parseHarvesterOutput(raw: string): Record<string, unknown>[] {
  const data = JSON.parse(raw) as HarvesterOutput
  const results: Record<string, unknown>[] = []

  for (const email of data.emails ?? []) {
    results.push({ type: 'email', value: email, source: 'theHarvester' })
  }

  for (const host of data.hosts ?? []) {
    results.push({ type: 'host', value: host, source: 'theHarvester' })
  }

  for (const ip of data.ips ?? []) {
    results.push({ type: 'ip', value: ip, source: 'theHarvester' })
  }

  for (const asn of data.asns ?? []) {
    results.push({ type: 'asn', value: asn, source: 'theHarvester' })
  }

  return results
}

cli({
  provider: 'recon',
  name: 'osint-harvest',
  description: 'Gather emails, subdomains, and IPs from public sources using theHarvester',
  strategy: Strategy.FREE,
  domain: 'recon',
  args: {
    domain: { type: 'string', required: true, help: 'Target domain' },
    sources: {
      type: 'string',
      default: 'all',
      help: 'Data sources (e.g., google,bing,shodan,virustotal)',
    },
    limit: { type: 'number', default: 100, help: 'Maximum results per source' },
  },
  columns: ['type', 'value', 'source'],
  timeout: 300,

  async func(ctx: ExecContext, args: Record<string, unknown>) {
    const domain = args.domain as string
    const sources = (args.sources as string) ?? 'all'
    const limit = (args.limit as number) ?? 100

    if (!(await checkToolInstalled('theHarvester'))) {
      throw new ToolNotFoundError('theHarvester', 'pip install theHarvester')
    }

    const tmpBase = `/tmp/tharvest-${randomBytes(8).toString('hex')}`

    try {
      await runTool({
        tool: 'theHarvester',
        args: [
          '-d', domain,
          '-b', sources,
          '-l', String(limit),
          '-f', tmpBase,
        ],
        timeout: 300,
        allowNonZero: true,
      })

      const raw = await readFile(`${tmpBase}.json`, 'utf-8')
      const findings = parseHarvesterOutput(raw)

      ctx.log.info(`theHarvester found ${findings.length} results for ${domain}`)
      return findings
    } finally {
      for (const ext of ['.json', '.xml']) {
        try { await unlink(`${tmpBase}${ext}`) } catch { /* tmp cleanup, ignore */ }
      }
    }
  },
})
