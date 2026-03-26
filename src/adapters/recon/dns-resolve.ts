/**
 * DNS resolution adapter.
 * Wraps: dnsx (ProjectDiscovery DNS resolver)
 * Output: JSONL
 */

import { cli, Strategy } from '../../registry.js'
import type { ExecContext } from '../../types.js'
import { runExternalTool } from '../_utils/tool-runner.js'
import { parseJsonLines } from '../_utils/tool-runner.js'

cli({
  provider: 'recon',
  name: 'dns-resolve',
  description: 'Resolve domains to IPs with DNS record details using dnsx',
  strategy: Strategy.FREE,
  domain: 'recon',
  args: {
    target: {
      type: 'string',
      required: true,
      help: 'Domain or file with domains (one per line)',
    },
    record_type: {
      type: 'string',
      default: 'a',
      help: 'Record types: a, aaaa, cname, mx, ns, txt, ptr',
    },
  },
  columns: ['host', 'a', 'aaaa', 'cname', 'mx', 'status'],
  timeout: 120,

  async func(ctx: ExecContext, args: Record<string, unknown>) {
    const target = args.target as string
    const recordType = args.record_type as string

    const { results } = await runExternalTool({
      tools: ['dnsx'],
      buildArgs: () => {
        const a = ['-json', '-silent', '-resp']
        // Add record type flags
        for (const rt of recordType.split(',')) {
          a.push(`-${rt.trim()}`)
        }
        if (target.endsWith('.txt')) a.push('-l', target)
        else a.push('-d', target)
        return a
      },
      installHint: 'go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest',
      parseOutput: (stdout) =>
        parseJsonLines(stdout).map((r) => ({
          host: r.host ?? '',
          a: Array.isArray(r.a) ? (r.a as string[]).join(', ') : '',
          aaaa: Array.isArray(r.aaaa) ? (r.aaaa as string[]).join(', ') : '',
          cname: Array.isArray(r.cname)
            ? (r.cname as string[]).join(', ')
            : '',
          mx: Array.isArray(r.mx) ? (r.mx as string[]).join(', ') : '',
          status: r.status_code ?? 'NOERROR',
        })),
    })

    ctx.log.info(`Resolved ${results.length} hosts`)
    return results
  },
})
