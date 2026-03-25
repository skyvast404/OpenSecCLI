/**
 * API endpoint discovery adapter.
 * Wraps: kiterunner (primary), ffuf (fallback)
 * Source: pentest-api-deep
 */

import { cli, Strategy } from '../../registry.js'
import type { ExecContext } from '../../types.js'
import { ToolNotFoundError } from '../../errors.js'
import { runTool, findAvailableTool, parseJsonLines } from '../_utils/tool-runner.js'

cli({
  provider: 'vuln',
  name: 'api-discover',
  description: 'Discover API endpoints using kiterunner or ffuf with API wordlists',
  strategy: Strategy.FREE,
  args: {
    target: { type: 'string', required: true, help: 'Target URL' },
    wordlist: { type: 'string', required: false, help: 'API wordlist path' },
  },
  columns: ['method', 'path', 'status', 'length', 'source'],
  timeout: 300,

  async func(ctx: ExecContext, args: Record<string, unknown>) {
    const target = args.target as string
    const wordlist = args.wordlist as string | undefined

    const tool = await findAvailableTool(['kr', 'kiterunner', 'ffuf'])
    if (!tool) throw new ToolNotFoundError('kr, kiterunner, ffuf', 'kiterunner or ffuf')

    if (tool === 'kr' || tool === 'kiterunner') {
      const krArgs = ['scan', target, '--json']
      if (wordlist) krArgs.push('-w', wordlist)
      const result = await runTool({ tool, args: krArgs, timeout: 300, allowNonZero: true })
      const endpoints = parseJsonLines(result.stdout).map((r) => ({
        method: r.method ?? 'GET',
        path: r.path ?? r.url,
        status: r.status_code ?? r.status,
        length: r.length ?? 0,
        source: 'kiterunner',
      }))
      ctx.log.info(`Kiterunner found ${endpoints.length} API endpoints`)
      return endpoints
    }

    // ffuf with API wordlist
    const ffufArgs = ['-u', `${target}/FUZZ`, '-of', 'json', '-o', '/dev/stdout', '-mc', 'all', '-fc', '404,405']
    if (wordlist) {
      ffufArgs.push('-w', wordlist)
    } else {
      ffufArgs.push('-w', '/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt')
    }

    const result = await runTool({ tool: 'ffuf', args: ffufArgs, timeout: 300, allowNonZero: true })
    try {
      const output = JSON.parse(result.stdout) as { results?: Array<Record<string, unknown>> }
      const endpoints = (output.results ?? []).map((r) => ({
        method: 'GET',
        path: r.url,
        status: r.status,
        length: r.length ?? 0,
        source: 'ffuf',
      }))
      ctx.log.info(`ffuf found ${endpoints.length} API endpoints`)
      return endpoints
    } catch {
      return []
    }
  },
})
