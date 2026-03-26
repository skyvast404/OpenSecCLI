/**
 * Wayback Machine historical URL fetching adapter.
 * Wraps: waybackurls
 */

import { cli, Strategy } from '../../registry.js'
import type { ExecContext } from '../../types.js'
import { runExternalTool, parseTextLines } from '../_utils/tool-runner.js'

export function parseWaybackurlsOutput(stdout: string): Record<string, unknown>[] {
  const lines = parseTextLines(stdout)
  const unique = [...new Set(lines)]
  return unique.map((url) => ({ url }))
}

cli({
  provider: 'recon',
  name: 'wayback-urls',
  description: 'Fetch historical URLs from Wayback Machine',
  strategy: Strategy.FREE,
  domain: 'recon',
  args: {
    domain: { type: 'string', required: true, help: 'Target domain to fetch historical URLs for' },
  },
  columns: ['url'],
  timeout: 120,

  async func(ctx: ExecContext, args: Record<string, unknown>) {
    const domain = args.domain as string

    const { results } = await runExternalTool({
      tools: ['waybackurls'],
      buildArgs: () => [domain],
      installHint: 'go install github.com/tomnomnom/waybackurls@latest',
      parseOutput: (stdout) => parseWaybackurlsOutput(stdout),
      allowNonZero: true,
      timeout: 120,
    })

    ctx.log.info(`waybackurls found ${results.length} unique URLs for ${domain}`)
    return results
  },
})
