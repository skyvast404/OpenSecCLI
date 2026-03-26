import { describe, it, expect } from 'vitest'
import { parseCSP, analyzeCSP } from '../../src/adapters/vuln/csp-parser.js'

describe('CSP parser', () => {
  it('parses directives into structured object', () => {
    const csp =
      "default-src 'self'; script-src 'self' cdn.example.com; style-src 'unsafe-inline'"
    const parsed = parseCSP(csp)
    expect(parsed['default-src']).toEqual(["'self'"])
    expect(parsed['script-src']).toEqual(["'self'", 'cdn.example.com'])
    expect(parsed['style-src']).toEqual(["'unsafe-inline'"])
  })

  it('detects unsafe-inline in script-src as high', () => {
    const result = analyzeCSP("script-src 'self' 'unsafe-inline'")
    const issue = result.findings.find((f) => f.id === 'CSP-UNSAFE-INLINE')
    expect(issue).toBeDefined()
    expect(issue!.severity).toBe('high')
  })

  it('detects unsafe-eval as high', () => {
    const result = analyzeCSP("script-src 'self' 'unsafe-eval'")
    expect(result.findings.some((f) => f.id === 'CSP-UNSAFE-EVAL')).toBe(true)
  })

  it('detects wildcard sources as critical', () => {
    const result = analyzeCSP('script-src *')
    const issue = result.findings.find((f) => f.id === 'CSP-WILDCARD')
    expect(issue).toBeDefined()
    expect(issue!.severity).toBe('critical')
  })

  it('detects data: scheme in script-src', () => {
    const result = analyzeCSP("script-src 'self' data:")
    expect(result.findings.some((f) => f.id === 'CSP-DATA-SCHEME')).toBe(true)
  })

  it('detects http: source as mixed content', () => {
    const result = analyzeCSP('script-src http://cdn.example.com')
    expect(result.findings.some((f) => f.id === 'CSP-HTTP-SOURCE')).toBe(true)
  })

  it('detects missing base-uri', () => {
    const result = analyzeCSP("default-src 'self'")
    expect(result.findings.some((f) => f.id === 'CSP-NO-BASE-URI')).toBe(true)
  })

  it('detects missing object-src when default-src is not none', () => {
    const result = analyzeCSP("default-src 'self'")
    expect(result.findings.some((f) => f.id === 'CSP-NO-OBJECT-SRC')).toBe(
      true,
    )
  })

  it('does not flag object-src when default-src is none', () => {
    const result = analyzeCSP(
      "default-src 'none'; script-src 'self'; base-uri 'none'",
    )
    expect(result.findings.some((f) => f.id === 'CSP-NO-OBJECT-SRC')).toBe(
      false,
    )
  })

  it('passes strict CSP with no findings', () => {
    const result = analyzeCSP(
      "default-src 'none'; script-src 'self'; style-src 'self'; base-uri 'none'; object-src 'none'; form-action 'self'",
    )
    expect(result.findings).toHaveLength(0)
    expect(result.grade).toBe('A')
  })

  it('grades CSP from A to F', () => {
    expect(
      analyzeCSP(
        "default-src 'none'; script-src 'self'; base-uri 'none'; object-src 'none'",
      ).grade,
    ).toBe('A')
    expect(analyzeCSP("default-src 'self'").grade).toBe('B') // missing base-uri (-10), object-src (-10) = score 80
    expect(analyzeCSP('script-src *').grade).toBe('C') // wildcard (-30), no base-uri (-10), no object-src (-10) = score 50
    expect(analyzeCSP("script-src * 'unsafe-inline' 'unsafe-eval' data:").grade).toBe('F') // wildcard + unsafe-inline + unsafe-eval + data = score 0
  })

  it('handles empty policy string', () => {
    const parsed = parseCSP('')
    expect(Object.keys(parsed)).toHaveLength(0)
  })

  it('handles policy with trailing semicolons', () => {
    const parsed = parseCSP("default-src 'self';;; script-src 'self';")
    expect(parsed['default-src']).toEqual(["'self'"])
    expect(parsed['script-src']).toEqual(["'self'"])
  })
})
