/**
 * Subdomain enumeration adapter.
 * Wraps: subfinder (primary), amass (fallback)
 * Source: pentest-osint-recon
 */

import { cli, Strategy } from '../../registry.js'
import type { ExecContext } from '../../types.js'
import { runExternalTool } from '../_utils/tool-runner.js'
import { parseSubfinderOutput } from './parsers.js'

cli({
  provider: 'recon',
  name: 'subdomain-enum',
  description: 'Enumerate subdomains for a target domain using subfinder/amass',
  strategy: Strategy.FREE,
  args: {
    domain: { type: 'string', required: true, help: 'Target domain (e.g., example.com)' },
    recursive: { type: 'boolean', default: false, help: 'Enable recursive enumeration' },
  },
  columns: ['subdomain', 'source'],
  timeout: 300,

  async func(ctx: ExecContext, args: Record<string, unknown>) {
    const domain = args.domain as string
    const recursive = args.recursive as boolean

    const { results } = await runExternalTool({
      tools: ['subfinder', 'amass'],
      buildArgs: (tool) => {
        if (tool === 'subfinder') {
          const a = ['-d', domain, '-json', '-silent']
          if (recursive) a.push('-recursive')
          return a
        }
        return ['enum', '-passive', '-d', domain]
      },
      parseOutput: parseSubfinderOutput,
    })

    ctx.log.info(`Found ${results.length} subdomains for ${domain}`)

    // Deduplicate by subdomain
    const seen = new Set<string>()
    return results.filter((r) => {
      const sub = r.subdomain as string
      if (seen.has(sub)) return false
      seen.add(sub)
      return true
    })
  },
})
