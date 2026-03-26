/**
 * CRLF injection scanning adapter.
 * Wraps: crlfuzz
 */

import { cli, Strategy } from '../../registry.js'
import type { ExecContext } from '../../types.js'
import { runExternalTool, parseJsonLines } from '../_utils/tool-runner.js'

interface CrlfuzzLine {
  url?: string
  vulnerable?: boolean
  payload?: string
}

export function parseCrlfuzzOutput(stdout: string): Record<string, unknown>[] {
  const lines = parseJsonLines(stdout)
  return lines.map((line) => {
    const entry = line as unknown as CrlfuzzLine
    return {
      url: entry.url ?? '',
      vulnerable: entry.vulnerable ?? false,
      payload: entry.payload ?? '',
    }
  })
}

cli({
  provider: 'vuln',
  name: 'crlf-scan',
  description: 'Scan for CRLF injection vulnerabilities using crlfuzz',
  strategy: Strategy.FREE,
  domain: 'vuln-scan',
  args: {
    url: { type: 'string', required: true, help: 'Target URL to scan for CRLF injection' },
  },
  columns: ['url', 'vulnerable', 'payload'],
  timeout: 120,

  async func(ctx: ExecContext, args: Record<string, unknown>) {
    const url = args.url as string

    const { results } = await runExternalTool({
      tools: ['crlfuzz'],
      buildArgs: () => ['-u', url, '-json', '-silent'],
      installHint: 'go install github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest',
      parseOutput: (stdout) => parseCrlfuzzOutput(stdout),
      allowNonZero: true,
      timeout: 120,
    })

    ctx.log.info(`crlfuzz found ${results.length} results for ${url}`)
    return results
  },
})
