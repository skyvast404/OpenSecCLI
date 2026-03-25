/**
 * HTTP security header auditor.
 * Pure TypeScript -- no external dependencies.
 * Source: pentest-config-hardening
 */

import { cli, Strategy } from '../../registry.js'
import type { ExecContext } from '../../types.js'
import { auditHeaders } from './parsers.js'

cli({
  provider: 'vuln',
  name: 'header-audit',
  description: 'Audit HTTP security headers (HSTS, CSP, X-Frame-Options, etc.)',
  strategy: Strategy.FREE,
  args: {
    url: { type: 'string', required: true, help: 'Target URL to audit' },
  },
  columns: ['header', 'status', 'value', 'severity', 'recommendation'],
  timeout: 30,

  async func(ctx: ExecContext, args: Record<string, unknown>) {
    const url = args.url as string

    ctx.log.info(`Auditing security headers for ${url}`)

    const response = await fetch(url, {
      method: 'HEAD',
      redirect: 'follow',
      signal: AbortSignal.timeout(15_000),
    })

    const headers: Record<string, string> = {}
    response.headers.forEach((value, key) => {
      headers[key.toLowerCase()] = value
    })

    const results = auditHeaders(url, headers)
    const missing = results.filter((r) => r.status === 'MISSING').length
    const weak = results.filter((r) => r.status === 'WEAK').length

    ctx.log.info(`Audit complete: ${missing} missing, ${weak} weak, ${results.length - missing - weak} present`)
    return results
  },
})
