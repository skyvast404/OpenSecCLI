/**
 * HTTP security header auditor.
 * Pure TypeScript -- no external dependencies.
 * Source: pentest-config-hardening
 */

import { cli, Strategy } from '../../registry.js'
import type { ExecContext } from '../../types.js'
import { auditHeaders } from './parsers.js'
import { analyzeCSP } from './csp-parser.js'
import { analyzeCookies } from './cookie-analyzer.js'

interface ScoredResult {
  header: string
  status: string
  value: string
  severity: string
  recommendation: string
  score?: number
  grade?: string
  [key: string]: unknown
}

function computeOverallScore(
  results: ReadonlyArray<{ severity: string; status: string }>,
): { score: number; grade: string } {
  let score = 100
  for (const r of results) {
    if (r.status === 'PRESENT' || r.status === 'info') continue
    if (r.severity === 'critical') score -= 15
    else if (r.severity === 'high') score -= 10
    else if (r.severity === 'medium') score -= 5
    else if (r.severity === 'low') score -= 2
  }
  score = Math.max(0, Math.min(100, score))

  const grade =
    score >= 90
      ? 'A'
      : score >= 70
        ? 'B'
        : score >= 50
          ? 'C'
          : score >= 30
            ? 'D'
            : 'F'

  return { score, grade }
}

cli({
  provider: 'vuln',
  name: 'header-audit',
  description: 'Audit HTTP security headers (HSTS, CSP, X-Frame-Options, etc.)',
  strategy: Strategy.FREE,
  domain: 'vuln-scan',
  args: {
    url: { type: 'string', required: true, help: 'Target URL to audit' },
  },
  columns: [
    'header',
    'status',
    'value',
    'severity',
    'recommendation',
    'score',
    'grade',
  ],
  timeout: 30,

  async func(ctx: ExecContext, args: Record<string, unknown>) {
    const url = args.url as string

    ctx.log.info(`Auditing security headers for ${url}`)

    const response = await fetch(url, {
      method: 'GET',
      redirect: 'follow',
      signal: AbortSignal.timeout(15_000),
    })

    const headers: Record<string, string> = {}
    response.headers.forEach((value, key) => {
      headers[key.toLowerCase()] = value
    })

    const headerResults = auditHeaders(url, headers)

    const results: ScoredResult[] = headerResults.map((r) => ({
      header: r.header,
      status: r.status,
      value: r.value,
      severity: r.severity,
      recommendation: r.recommendation,
    }))

    // CSP deep analysis
    const cspValue = response.headers.get('content-security-policy')
    if (cspValue) {
      const cspAnalysis = analyzeCSP(cspValue)
      for (const finding of cspAnalysis.findings) {
        results.push({
          header: `CSP: ${finding.directive}`,
          status: 'WEAK',
          value: finding.message,
          severity: finding.severity,
          recommendation: `Fix ${finding.directive} directive`,
        })
      }
    }

    // Cookie analysis
    const cookies = response.headers.getSetCookie?.() ?? []
    for (const cookie of cookies) {
      const cookieFindings = analyzeCookies(cookie)
      for (const f of cookieFindings) {
        results.push({
          header: `Cookie: ${f.cookie_name}`,
          status: 'WEAK',
          value: f.detail,
          severity: f.severity,
          recommendation: '',
        })
      }
    }

    // Overall grade as first row
    const { score, grade } = computeOverallScore(results)
    results.unshift({
      header: 'OVERALL GRADE',
      status: grade,
      value: `${score}/100`,
      severity: 'info',
      recommendation: '',
      score,
      grade,
    })

    const missing = results.filter((r) => r.status === 'MISSING').length
    const weak = results.filter((r) => r.status === 'WEAK').length

    ctx.log.info(
      `Audit complete: ${missing} missing, ${weak} weak, grade ${grade} (${score}/100)`,
    )
    return results
  },
})
