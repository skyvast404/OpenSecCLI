/**
 * Technology fingerprinting adapter.
 * Wraps: httpx (primary), whatweb (fallback)
 * Source: pentest-osint-recon, pentest-recon-attack-surface
 */

import { cli, Strategy } from '../../registry.js'
import type { ExecContext } from '../../types.js'
import { ToolNotFoundError } from '../../errors.js'
import { runTool, findAvailableTool } from '../_utils/tool-runner.js'
import { parseHttpxOutput } from './parsers.js'
import { parseJsonLines } from '../_utils/tool-runner.js'

cli({
  provider: 'recon',
  name: 'tech-fingerprint',
  description: 'Identify technologies, web servers, and frameworks on target URLs',
  strategy: Strategy.FREE,
  args: {
    target: { type: 'string', required: true, help: 'URL or file with URLs (one per line)' },
  },
  columns: ['url', 'status', 'title', 'technologies', 'server', 'content_length'],
  timeout: 120,

  async func(ctx: ExecContext, args: Record<string, unknown>) {
    const target = args.target as string
    const tool = await findAvailableTool(['httpx', 'whatweb'])
    if (!tool) throw new ToolNotFoundError('httpx, whatweb', 'httpx or whatweb')

    if (tool === 'httpx') {
      const isFile = target.includes('\n') || target.endsWith('.txt')
      const toolArgs = ['-json', '-silent', '-title', '-tech-detect', '-status-code', '-content-length', '-web-server']
      if (isFile) {
        toolArgs.push('-l', target)
      } else {
        toolArgs.push('-u', target)
      }
      const result = await runTool({ tool: 'httpx', args: toolArgs, timeout: 120 })
      return parseHttpxOutput(result.stdout)
    }

    // whatweb fallback
    const result = await runTool({
      tool: 'whatweb',
      args: ['--log-json=-', target],
      timeout: 60,
    })
    return parseJsonLines(result.stdout).map((r) => ({
      url: r.target,
      status: r.http_status,
      title: '',
      technologies: Object.keys((r.plugins as Record<string, unknown>) ?? {}).join(', '),
      server: '',
    }))
  },
})
