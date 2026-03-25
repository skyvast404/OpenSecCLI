/**
 * Content/directory discovery adapter.
 * Wraps: ffuf (primary), dirsearch (fallback)
 * Source: pentest-enterprise-web, pentest-recon-attack-surface
 */

import { cli, Strategy } from '../../registry.js'
import type { ExecContext } from '../../types.js'
import { ToolNotFoundError } from '../../errors.js'
import { runTool, findAvailableTool } from '../_utils/tool-runner.js'
import { parseFfufOutput } from './parsers.js'
import { parseJsonLines } from '../_utils/tool-runner.js'

cli({
  provider: 'recon',
  name: 'content-discover',
  description: 'Discover hidden endpoints, directories, and files via fuzzing',
  strategy: Strategy.FREE,
  domain: 'recon',
  args: {
    url: { type: 'string', required: true, help: 'Target URL (use FUZZ as placeholder, e.g., https://example.com/FUZZ)' },
    wordlist: { type: 'string', required: false, help: 'Path to wordlist (default: tool built-in)' },
    extensions: { type: 'string', required: false, help: 'File extensions to try (e.g., "php,html,js")' },
    threads: { type: 'number', required: false, default: 40, help: 'Concurrent threads' },
  },
  columns: ['url', 'status', 'length', 'words'],
  timeout: 300,

  async func(ctx: ExecContext, args: Record<string, unknown>) {
    const url = args.url as string
    const wordlist = args.wordlist as string | undefined
    const extensions = args.extensions as string | undefined
    const threads = args.threads as number

    const tool = await findAvailableTool(['ffuf', 'dirsearch', 'feroxbuster'])
    if (!tool) throw new ToolNotFoundError('ffuf, dirsearch, feroxbuster', 'ffuf, dirsearch, or feroxbuster')

    try {
      if (tool === 'ffuf') {
        const ffufArgs = ['-u', url, '-o', '/dev/stdout', '-of', 'json', '-t', String(threads), '-mc', 'all', '-fc', '404']
        if (wordlist) ffufArgs.push('-w', wordlist)
        else ffufArgs.push('-w', '/usr/share/seclists/Discovery/Web-Content/common.txt')
        if (extensions) ffufArgs.push('-e', extensions)

        const result = await runTool({ tool: 'ffuf', args: ffufArgs, timeout: 300, allowNonZero: true })
        const parsed = parseFfufOutput(result.stdout)
        ctx.log.info(`Discovered ${parsed.length} endpoints`)
        return parsed
      }

      if (tool === 'dirsearch') {
        const dsArgs = ['-u', url, '--format', 'json', '-o', '/dev/stdout', '-t', String(threads)]
        if (wordlist) dsArgs.push('-w', wordlist)
        if (extensions) dsArgs.push('-e', extensions)

        const result = await runTool({ tool: 'dirsearch', args: dsArgs, timeout: 300, allowNonZero: true })
        return parseJsonLines(result.stdout).map((r) => ({
          url: r.url,
          status: r.status,
          length: r['content-length'] ?? 0,
          words: 0,
        }))
      }

      // feroxbuster
      const fbArgs = ['-u', url, '--json', '-t', String(threads), '-q']
      if (wordlist) fbArgs.push('-w', wordlist)
      if (extensions) fbArgs.push('-x', extensions)

      const result = await runTool({ tool: 'feroxbuster', args: fbArgs, timeout: 300, allowNonZero: true })
      return parseJsonLines(result.stdout).map((r) => ({
        url: r.url,
        status: r.status_code,
        length: r.content_length ?? 0,
        words: r.word_count ?? 0,
      }))
    } catch (error) {
      const msg = (error as Error).message ?? ''
      if (msg.includes('ENOENT')) {
        throw new Error(`Failed to run ${tool}: executable not found or has a broken shebang. Reinstall the tool.`)
      }
      throw error
    }
  },
})
