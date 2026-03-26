/**
 * Hidden HTTP parameter discovery adapter.
 * Wraps: arjun
 * Source: pentest-recon-attack-surface
 */

import { cli, Strategy } from '../../registry.js'
import type { ExecContext } from '../../types.js'
import { ToolNotFoundError } from '../../errors.js'
import { runTool, checkToolInstalled } from '../_utils/tool-runner.js'
import { randomBytes } from 'node:crypto'
import { readFile, unlink } from 'node:fs/promises'

interface ArjunOutput {
  [url: string]: {
    [method: string]: string[]
  }
}

/**
 * Parse Arjun JSON output into table rows.
 */
export function parseArjunOutput(raw: string): Record<string, unknown>[] {
  const data = JSON.parse(raw) as ArjunOutput
  const results: Record<string, unknown>[] = []

  for (const [url, methods] of Object.entries(data)) {
    for (const [method, params] of Object.entries(methods)) {
      for (const param of params) {
        results.push({
          url,
          method,
          parameter: param,
          source: 'arjun',
        })
      }
    }
  }

  return results
}

cli({
  provider: 'recon',
  name: 'param-discover',
  description: 'Discover hidden HTTP parameters using Arjun',
  strategy: Strategy.FREE,
  domain: 'recon',
  args: {
    url: { type: 'string', required: true, help: 'Target URL' },
    method: {
      type: 'string',
      default: 'GET',
      choices: ['GET', 'POST', 'JSON'],
      help: 'HTTP method',
    },
  },
  columns: ['url', 'method', 'parameter', 'source'],
  timeout: 300,

  async func(ctx: ExecContext, args: Record<string, unknown>) {
    const url = args.url as string
    const method = (args.method as string) ?? 'GET'

    if (!(await checkToolInstalled('arjun'))) {
      throw new ToolNotFoundError('arjun', 'pip install arjun')
    }

    const tmpFile = `/tmp/arjun-${randomBytes(8).toString('hex')}.json`

    try {
      await runTool({
        tool: 'arjun',
        args: ['-u', url, '-m', method, '-oJ', tmpFile],
        timeout: 300,
        allowNonZero: true,
      })

      const raw = await readFile(tmpFile, 'utf-8')
      const findings = parseArjunOutput(raw)

      ctx.log.info(`Arjun discovered ${findings.length} parameters for ${url}`)
      return findings
    } finally {
      try { await unlink(tmpFile) } catch { /* tmp cleanup, ignore */ }
    }
  },
})
