/**
 * URL crawling adapter.
 * Wraps: katana (ProjectDiscovery web crawler)
 * Output: JSONL
 */

import { cli, Strategy } from '../../registry.js'
import type { ExecContext } from '../../types.js'
import { runExternalTool } from '../_utils/tool-runner.js'
import { parseJsonLines } from '../_utils/tool-runner.js'

cli({
  provider: 'recon',
  name: 'url-crawl',
  description: 'Crawl web application and extract URLs, endpoints, and JS files using katana',
  strategy: Strategy.FREE,
  domain: 'recon',
  args: {
    url: { type: 'string', required: true, help: 'Target URL to crawl' },
    depth: { type: 'number', default: 3, help: 'Maximum crawl depth' },
    js: { type: 'boolean', default: true, help: 'Enable JavaScript parsing' },
  },
  columns: ['url', 'method', 'source', 'status'],
  timeout: 300,

  async func(ctx: ExecContext, args: Record<string, unknown>) {
    const url = args.url as string
    const depth = args.depth as number
    const js = args.js as boolean

    const { results } = await runExternalTool({
      tools: ['katana'],
      buildArgs: () => {
        const a = ['-u', url, '-jsonl', '-silent', '-d', String(depth)]
        if (js) a.push('-jc')
        return a
      },
      installHint: 'go install github.com/projectdiscovery/katana/cmd/katana@latest',
      parseOutput: (stdout) =>
        parseJsonLines(stdout).map((r) => ({
          url:
            (r.request as Record<string, unknown>)?.endpoint ??
            r.endpoint ??
            r.url ??
            '',
          method: (r.request as Record<string, unknown>)?.method ?? 'GET',
          source: r.source ?? '',
          status:
            (r.response as Record<string, unknown>)?.status_code ??
            r.status_code ??
            0,
        })),
    })

    ctx.log.info(`Crawled ${results.length} URLs from ${url}`)
    return results
  },
})
