/**
 * CORS misconfiguration checker.
 * Pure TypeScript -- sends crafted Origin headers.
 * Source: pentest-client-advanced
 */

import { cli, Strategy } from '../../registry.js'
import type { ExecContext } from '../../types.js'

interface CorsResult {
  url: string
  test: string
  origin_sent: string
  acao: string
  acac: string
  vulnerable: boolean
  severity: string
  [key: string]: unknown
}

const CORS_TESTS: ReadonlyArray<{
  name: string
  origin: (domain: string) => string
  severity: string
}> = [
  { name: 'reflected-origin', origin: (domain) => `https://evil-${domain}`, severity: 'critical' },
  { name: 'null-origin', origin: () => 'null', severity: 'high' },
  { name: 'subdomain-wildcard', origin: (domain) => `https://attacker.${domain}`, severity: 'high' },
  { name: 'http-downgrade', origin: (domain) => `http://${domain}`, severity: 'medium' },
  { name: 'third-party', origin: () => 'https://evil.com', severity: 'critical' },
]

cli({
  provider: 'vuln',
  name: 'cors-check',
  description: 'Test for CORS misconfigurations (reflected origin, null bypass, wildcard)',
  strategy: Strategy.FREE,
  domain: 'vuln-scan',
  args: {
    url: { type: 'string', required: true, help: 'Target URL to test' },
  },
  columns: ['test', 'origin_sent', 'acao', 'acac', 'vulnerable', 'severity'],
  timeout: 30,

  async func(ctx: ExecContext, args: Record<string, unknown>) {
    const url = args.url as string
    const urlObj = new URL(url)
    const domain = urlObj.hostname

    ctx.log.info(`Testing CORS configuration for ${url}`)

    const results: CorsResult[] = []

    for (const test of CORS_TESTS) {
      const origin = test.origin(domain)
      try {
        const response = await fetch(url, {
          method: 'GET',
          headers: { Origin: origin },
          redirect: 'follow',
          signal: AbortSignal.timeout(10_000),
        })

        const acao = response.headers.get('access-control-allow-origin') ?? ''
        const acac = response.headers.get('access-control-allow-credentials') ?? ''

        const vulnerable = acao === origin || (acao === '*' && acac === 'true')

        results.push({
          url,
          test: test.name,
          origin_sent: origin,
          acao,
          acac,
          vulnerable,
          severity: vulnerable ? test.severity : 'info',
        })
      } catch {
        results.push({
          url,
          test: test.name,
          origin_sent: origin,
          acao: 'error',
          acac: '',
          vulnerable: false,
          severity: 'info',
        })
      }
    }

    const vulnCount = results.filter((r) => r.vulnerable).length
    ctx.log.info(`CORS check complete: ${vulnCount} vulnerable configurations found`)
    return results
  },
})
