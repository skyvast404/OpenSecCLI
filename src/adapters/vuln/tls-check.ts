/**
 * TLS configuration checker.
 * Wraps: testssl.sh (primary), nmap ssl-enum-ciphers (fallback)
 * Source: pentest-config-hardening
 */

import { cli, Strategy } from '../../registry.js'
import type { ExecContext } from '../../types.js'
import { ToolNotFoundError } from '../../errors.js'
import { runTool, findAvailableTool } from '../_utils/tool-runner.js'
import { parseTlsCheckOutput } from './parsers.js'

cli({
  provider: 'vuln',
  name: 'tls-check',
  description: 'Check TLS/SSL configuration for weak ciphers, protocols, and certificate issues',
  strategy: Strategy.FREE,
  args: {
    host: { type: 'string', required: true, help: 'Target hostname[:port] (default port 443)' },
  },
  columns: ['id', 'finding', 'severity', 'cve'],
  timeout: 120,

  async func(ctx: ExecContext, args: Record<string, unknown>) {
    const host = args.host as string
    const tool = await findAvailableTool(['testssl.sh', 'testssl', 'nmap'])
    if (!tool) throw new ToolNotFoundError('testssl.sh, nmap', 'testssl.sh or nmap')

    if (tool === 'testssl.sh' || tool === 'testssl') {
      const result = await runTool({
        tool,
        args: ['--jsonfile', '-', '--quiet', host],
        timeout: 120,
        allowNonZero: true,
      })
      return parseTlsCheckOutput(result.stdout)
    }

    // nmap fallback
    const result = await runTool({
      tool: 'nmap',
      args: ['--script', 'ssl-enum-ciphers', '-p', '443', host, '-oX', '-'],
      timeout: 60,
    })
    const lines = result.stdout.split('\n').filter((l) =>
      l.includes('TLS') || l.includes('SSL') || l.includes('cipher'),
    )
    return lines.map((line) => ({
      finding: line.trim(),
      severity: line.includes('WEAK') || line.includes('SSLv') || line.includes('TLSv1.0') ? 'high' : 'info',
    }))
  },
})
