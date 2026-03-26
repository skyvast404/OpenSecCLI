/**
 * URL archive adapter.
 * Wraps: gau (Get All URLs)
 * Output: plain text (one URL per line)
 */

import { cli, Strategy } from '../../registry.js'
import type { ExecContext } from '../../types.js'
import { runExternalTool } from '../_utils/tool-runner.js'

cli({
  provider: 'recon',
  name: 'url-archive',
  description:
    'Fetch known URLs from Wayback Machine, AlienVault OTX, and Common Crawl using gau',
  strategy: Strategy.FREE,
  domain: 'recon',
  args: {
    domain: { type: 'string', required: true, help: 'Target domain' },
    subs: { type: 'boolean', default: true, help: 'Include subdomains' },
  },
  columns: ['url'],
  timeout: 120,

  async func(ctx: ExecContext, args: Record<string, unknown>) {
    const domain = args.domain as string
    const subs = args.subs as boolean

    const { results } = await runExternalTool({
      tools: ['gau'],
      buildArgs: () => {
        const a = [domain]
        if (subs) a.push('--subs')
        return a
      },
      installHint: 'go install github.com/lc/gau/v2/cmd/gau@latest',
      parseOutput: (stdout) => {
        // gau outputs plain text, one URL per line
        return stdout
          .split('\n')
          .filter((l) => l.trim())
          .map((url) => ({ url: url.trim() }))
      },
    })

    // Deduplicate
    const seen = new Set<string>()
    const deduped = results.filter((r) => {
      const u = r.url as string
      if (seen.has(u)) return false
      seen.add(u)
      return true
    })

    ctx.log.info(`Found ${deduped.length} archived URLs for ${domain}`)
    return deduped
  },
})
