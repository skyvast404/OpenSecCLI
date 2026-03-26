/**
 * Web crawling/spidering adapter.
 * Wraps: gospider
 */

import { cli, Strategy } from '../../registry.js'
import type { ExecContext } from '../../types.js'
import { runExternalTool, parseJsonLines } from '../_utils/tool-runner.js'

interface GospiderLine {
  output?: string
  type?: string
  source?: string
  status_code?: number
}

export function parseGospiderOutput(stdout: string): Record<string, unknown>[] {
  const lines = parseJsonLines(stdout)
  return lines.map((line) => {
    const entry = line as unknown as GospiderLine
    return {
      url: entry.output ?? '',
      source: entry.source ?? '',
      type: entry.type ?? '',
      status: entry.status_code ?? 0,
    }
  })
}

cli({
  provider: 'recon',
  name: 'web-spider',
  description: 'Fast web crawling with sitemap/robots.txt parsing using gospider',
  strategy: Strategy.FREE,
  domain: 'recon',
  args: {
    url: { type: 'string', required: true, help: 'Target URL to crawl' },
    depth: { type: 'number', default: 3, help: 'Maximum crawl depth' },
  },
  columns: ['url', 'source', 'type', 'status'],
  timeout: 120,

  async func(ctx: ExecContext, args: Record<string, unknown>) {
    const url = args.url as string
    const depth = (args.depth as number) ?? 3

    const { results } = await runExternalTool({
      tools: ['gospider'],
      buildArgs: () => ['-s', url, '--json', '-d', String(depth), '-q'],
      installHint: 'go install github.com/jaeles-project/gospider@latest',
      parseOutput: (stdout) => parseGospiderOutput(stdout),
      allowNonZero: true,
      timeout: 120,
    })

    ctx.log.info(`gospider found ${results.length} URLs from ${url}`)
    return results
  },
})
