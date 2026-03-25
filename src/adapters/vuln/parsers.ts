/**
 * Output parsers for vulnerability scanning tools.
 */

import { parseJsonLines } from '../_utils/tool-runner.js'

export function parseNucleiOutput(stdout: string): Record<string, unknown>[] {
  return parseJsonLines(stdout).map((r) => {
    const info = (r.info as Record<string, unknown>) ?? {}
    return {
      template: r['template-id'] ?? r.templateID,
      name: info.name ?? '',
      severity: info.severity ?? 'unknown',
      host: r.host ?? '',
      matched_url: r.matched ?? r['matched-at'] ?? '',
      tags: Array.isArray(info.tags) ? (info.tags as string[]).join(', ') : '',
      curl_command: r['curl-command'] ?? '',
    }
  })
}

export function parseNiktoOutput(stdout: string): Record<string, unknown>[] {
  const lines = stdout.split('\n').filter((l) => l.startsWith('+ '))
  return lines.map((line) => {
    const text = line.slice(2).trim()
    const osvdbMatch = text.match(/OSVDB-(\d+):/)
    return {
      finding: text,
      osvdb: osvdbMatch?.[1] ?? '',
      severity: text.toLowerCase().includes('vuln') ? 'high' : 'info',
    }
  })
}

export interface HeaderAuditResult {
  url: string
  header: string
  status: 'PRESENT' | 'MISSING' | 'WEAK'
  value: string
  recommendation: string
  severity: string
}

const SECURITY_HEADERS: ReadonlyArray<{
  header: string
  severity: string
  recommendation: string
  validate?: (value: string) => 'PRESENT' | 'WEAK'
}> = [
  {
    header: 'Strict-Transport-Security',
    severity: 'high',
    recommendation: 'Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
    validate: (v) => (parseInt(v.match(/max-age=(\d+)/)?.[1] ?? '0') >= 31536000 ? 'PRESENT' : 'WEAK'),
  },
  {
    header: 'Content-Security-Policy',
    severity: 'high',
    recommendation: "Add: Content-Security-Policy: default-src 'self'",
    validate: (v) => (v.includes("'unsafe-inline'") || v.includes("'unsafe-eval'") ? 'WEAK' : 'PRESENT'),
  },
  {
    header: 'X-Content-Type-Options',
    severity: 'medium',
    recommendation: 'Add: X-Content-Type-Options: nosniff',
    validate: (v) => (v.toLowerCase() === 'nosniff' ? 'PRESENT' : 'WEAK'),
  },
  {
    header: 'X-Frame-Options',
    severity: 'medium',
    recommendation: 'Add: X-Frame-Options: DENY or SAMEORIGIN',
    validate: (v) => (['deny', 'sameorigin'].includes(v.toLowerCase()) ? 'PRESENT' : 'WEAK'),
  },
  {
    header: 'Referrer-Policy',
    severity: 'low',
    recommendation: 'Add: Referrer-Policy: strict-origin-when-cross-origin',
  },
  {
    header: 'Permissions-Policy',
    severity: 'low',
    recommendation: 'Add: Permissions-Policy: geolocation=(), camera=(), microphone=()',
  },
  {
    header: 'X-XSS-Protection',
    severity: 'info',
    recommendation: 'Set to 0 (modern browsers use CSP instead). Avoid "1; mode=block" which has XSS edge cases.',
  },
]

export function auditHeaders(url: string, headers: Record<string, string>): HeaderAuditResult[] {
  const lowerHeaders: Record<string, string> = {}
  for (const [k, v] of Object.entries(headers)) {
    lowerHeaders[k.toLowerCase()] = v
  }

  return SECURITY_HEADERS.map((spec) => {
    const key = spec.header.toLowerCase()
    const value = lowerHeaders[key]

    if (!value) {
      return {
        url,
        header: spec.header,
        status: 'MISSING' as const,
        value: '',
        recommendation: spec.recommendation,
        severity: spec.severity,
      }
    }

    const status = spec.validate ? spec.validate(value) : 'PRESENT'
    return {
      url,
      header: spec.header,
      status,
      value,
      recommendation: status === 'WEAK' ? spec.recommendation : '',
      severity: status === 'WEAK' ? spec.severity : 'info',
    }
  })
}

export function parseTlsCheckOutput(stdout: string): Record<string, unknown>[] {
  try {
    const output = JSON.parse(stdout) as { scanResult?: Array<Record<string, unknown>> }
    return (output.scanResult ?? []).map((r) => ({
      id: r.id,
      finding: r.finding,
      severity: r.severity,
      cve: r.cve ?? '',
    }))
  } catch {
    const lines = stdout.split('\n').filter((l) =>
      l.includes('VULNERABLE') || l.includes('offered') || l.includes('NOT'),
    )
    return lines.map((line) => ({
      finding: line.trim(),
      severity: line.includes('VULNERABLE') ? 'high' : 'info',
    }))
  }
}
