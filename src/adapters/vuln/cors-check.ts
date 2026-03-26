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
  { name: 'prefix-match', origin: (domain) => `https://${domain}.evil.com`, severity: 'high' },
  { name: 'suffix-match', origin: (domain) => `https://evil${domain}`, severity: 'high' },
  { name: 'backslash-bypass', origin: (domain) => `https://evil.com%60.${domain}`, severity: 'high' },
  { name: 'special-chars', origin: (domain) => `https://${domain}_.evil.com`, severity: 'medium' },
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

    // Preflight check: does the server allow dangerous methods from cross-origin?
    try {
      const preflightResponse = await fetch(url, {
        method: 'OPTIONS',
        headers: {
          Origin: 'https://evil.com',
          'Access-Control-Request-Method': 'PUT',
          'Access-Control-Request-Headers': 'X-Custom-Header',
        },
        signal: AbortSignal.timeout(10_000),
      })
      const allowMethods = preflightResponse.headers.get('access-control-allow-methods') ?? ''
      const allowHeaders = preflightResponse.headers.get('access-control-allow-headers') ?? ''
      if (allowMethods.includes('PUT') || allowMethods.includes('DELETE')) {
        results.push({
          url,
          test: 'preflight-dangerous-methods',
          origin_sent: 'https://evil.com',
          acao: allowMethods,
          acac: allowHeaders,
          vulnerable: true,
          severity: 'high',
        })
      }
    } catch {
      // Preflight request failed — server may not support OPTIONS
    }

    const vulnCount = results.filter((r) => r.vulnerable).length
    ctx.log.info(`CORS check complete: ${vulnCount} vulnerable configurations found`)
    return results
  },
})
