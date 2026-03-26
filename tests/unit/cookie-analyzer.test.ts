import { describe, it, expect } from 'vitest'
import { analyzeCookies } from '../../src/adapters/vuln/cookie-analyzer.js'

describe('cookie analyzer', () => {
  it('flags missing Secure flag', () => {
    const results = analyzeCookies('session=abc; Path=/; HttpOnly')
    expect(results.some((r) => r.issue === 'MISSING_SECURE')).toBe(true)
  })

  it('flags missing HttpOnly on session cookie', () => {
    const results = analyzeCookies('session=abc; Path=/; Secure')
    expect(results.some((r) => r.issue === 'MISSING_HTTPONLY')).toBe(true)
  })

  it('flags missing SameSite', () => {
    const results = analyzeCookies('session=abc; Path=/; Secure; HttpOnly')
    expect(results.some((r) => r.issue === 'MISSING_SAMESITE')).toBe(true)
  })

  it('flags SameSite=None without Secure', () => {
    const results = analyzeCookies('session=abc; SameSite=None')
    expect(results.some((r) => r.issue === 'SAMESITE_NONE_NO_SECURE')).toBe(
      true,
    )
  })

  it('flags low entropy session values', () => {
    const results = analyzeCookies('session=123; Secure; HttpOnly; SameSite=Lax')
    expect(results.some((r) => r.issue === 'LOW_ENTROPY')).toBe(true)
  })

  it('passes well-configured cookie', () => {
    const results = analyzeCookies(
      'session=a3f8d2e91b7c4502; Secure; HttpOnly; SameSite=Lax; Path=/app',
    )
    const issues = results.filter((r) => r.severity !== 'info')
    expect(issues).toHaveLength(0)
  })

  it('uses medium severity for non-session cookies missing Secure', () => {
    const results = analyzeCookies('theme=dark; Path=/')
    const secureFinding = results.find((r) => r.issue === 'MISSING_SECURE')
    expect(secureFinding?.severity).toBe('medium')
  })

  it('does not flag HttpOnly for non-session cookies', () => {
    const results = analyzeCookies('theme=dark; Path=/; Secure; SameSite=Lax')
    expect(results.some((r) => r.issue === 'MISSING_HTTPONLY')).toBe(false)
  })

  it('detects session cookie names with various patterns', () => {
    for (const name of ['jwt_token', 'auth_cookie', 'PHPSESSID', 'mysid']) {
      const results = analyzeCookies(`${name}=short; Path=/`)
      const hasSessionCheck = results.some(
        (r) => r.issue === 'MISSING_HTTPONLY' || r.issue === 'LOW_ENTROPY',
      )
      expect(hasSessionCheck).toBe(true)
    }
  })
})
