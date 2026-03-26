/**
 * Cookie security analyzer.
 * Inspects Set-Cookie headers for missing security flags and weak configurations.
 */

export interface CookieFinding {
  cookie_name: string
  issue: string
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  detail: string
}

const SESSION_COOKIE_RE = /session|token|auth|jwt|sid/i

export function analyzeCookies(setCookieHeader: string): CookieFinding[] {
  const findings: CookieFinding[] = []
  const parts = setCookieHeader.split(';').map((p) => p.trim())
  const nameValue = parts[0]?.split('=') ?? []
  const name = nameValue[0] ?? 'unknown'
  const value = nameValue.slice(1).join('=')
  const flags = parts.slice(1).map((p) => p.toLowerCase())

  const hasSecure = flags.some((f) => f === 'secure')
  const hasHttpOnly = flags.some((f) => f === 'httponly')
  const sameSiteEntry = flags.find((f) => f.startsWith('samesite='))
  const sameSite = sameSiteEntry?.split('=')[1]
  const isSession = SESSION_COOKIE_RE.test(name)

  if (!hasSecure) {
    findings.push({
      cookie_name: name,
      issue: 'MISSING_SECURE',
      severity: isSession ? 'high' : 'medium',
      detail: 'Cookie transmitted over HTTP. Add Secure flag.',
    })
  }

  if (!hasHttpOnly && isSession) {
    findings.push({
      cookie_name: name,
      issue: 'MISSING_HTTPONLY',
      severity: 'high',
      detail:
        'Session cookie accessible via JavaScript. Add HttpOnly flag.',
    })
  }

  if (!sameSite) {
    findings.push({
      cookie_name: name,
      issue: 'MISSING_SAMESITE',
      severity: 'medium',
      detail:
        'Missing SameSite attribute. Vulnerable to CSRF. Add SameSite=Lax or Strict.',
    })
  }

  if (sameSite === 'none' && !hasSecure) {
    findings.push({
      cookie_name: name,
      issue: 'SAMESITE_NONE_NO_SECURE',
      severity: 'high',
      detail:
        'SameSite=None requires Secure flag. Cookie will be rejected by modern browsers.',
    })
  }

  if (isSession && value.length > 0) {
    const uniqueChars = new Set(value).size
    const entropy = uniqueChars / Math.max(value.length, 1)
    if (value.length < 16 || entropy < 0.3) {
      findings.push({
        cookie_name: name,
        issue: 'LOW_ENTROPY',
        severity: 'medium',
        detail: `Session value appears predictable (length=${value.length}, char diversity=${(entropy * 100).toFixed(0)}%). Use cryptographically random tokens.`,
      })
    }
  }

  return findings
}
