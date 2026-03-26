import { describe, it, expect } from 'vitest'
import {
  parseNucleiOutput,
  parseNiktoOutput,
  auditHeaders,
  parseTlsCheckOutput,
} from '../../src/adapters/vuln/parsers.js'

describe('vuln parsers', () => {
  describe('parseNucleiOutput', () => {
    it('parses nuclei JSONL output', () => {
      const input = JSON.stringify({
        'template-id': 'cve-2021-44228',
        info: { name: 'Log4Shell', severity: 'critical', tags: ['cve', 'rce'] },
        host: 'https://example.com',
        matched: 'https://example.com/api',
        'curl-command': 'curl ...',
      }) + '\n'
      const result = parseNucleiOutput(input)
      expect(result).toHaveLength(1)
      expect(result[0]).toMatchObject({
        template: 'cve-2021-44228',
        name: 'Log4Shell',
        severity: 'critical',
        host: 'https://example.com',
        matched_url: 'https://example.com/api',
      })
    })

    it('handles multiple JSONL lines', () => {
      const line1 = JSON.stringify({
        'template-id': 'cve-2021-44228',
        info: { name: 'Log4Shell', severity: 'critical' },
        host: 'https://a.com',
        matched: 'https://a.com/api',
      })
      const line2 = JSON.stringify({
        'template-id': 'tech-detect',
        info: { name: 'Nginx', severity: 'info' },
        host: 'https://b.com',
        matched: 'https://b.com/',
      })
      const result = parseNucleiOutput(`${line1}\n${line2}\n`)
      expect(result).toHaveLength(2)
      expect(result[1]).toMatchObject({ template: 'tech-detect', name: 'Nginx' })
    })

    it('skips empty and non-JSON lines', () => {
      const input = '\n[INF] scanning...\n' + JSON.stringify({
        'template-id': 'test',
        info: { name: 'Test', severity: 'low' },
        host: 'https://c.com',
      }) + '\n'
      const result = parseNucleiOutput(input)
      expect(result).toHaveLength(1)
    })
  })

  describe('parseNiktoOutput', () => {
    it('parses nikto text output', () => {
      const input = [
        '- Nikto v2.1.6',
        '+ Target IP: 93.184.216.34',
        '+ OSVDB-3092: /admin/: This might be interesting.',
        '+ OSVDB-3268: /icons/: Directory indexing found.',
      ].join('\n')
      const result = parseNiktoOutput(input)
      expect(result).toHaveLength(3)
      expect(result[1]).toMatchObject({
        osvdb: '3092',
      })
    })

    it('returns empty for no findings', () => {
      const input = '- Nikto v2.1.6\n- No issues found\n'
      const result = parseNiktoOutput(input)
      expect(result).toHaveLength(0)
    })
  })

  describe('parseTlsCheckOutput', () => {
    it('parses testssl.sh JSON output', () => {
      const input = JSON.stringify({
        scanResult: [
          { id: 'ssl2', finding: 'SSLv2 not offered', severity: 'OK', cve: '' },
          { id: 'heartbleed', finding: 'Heartbleed VULNERABLE', severity: 'CRITICAL', cve: 'CVE-2014-0160' },
        ],
      })
      const result = parseTlsCheckOutput(input)
      expect(result).toHaveLength(2)
      expect(result[1]).toMatchObject({
        id: 'heartbleed',
        severity: 'CRITICAL',
        cve: 'CVE-2014-0160',
      })
    })

    it('falls back to text parsing', () => {
      const input = 'SSLv2 NOT offered\nTLSv1.0 offered (VULNERABLE)\nTLSv1.2 offered\n'
      const result = parseTlsCheckOutput(input)
      expect(result.length).toBeGreaterThan(0)
      const vulnLine = result.find((r) => (r.severity as string) === 'high')
      expect(vulnLine).toBeDefined()
    })
  })

  describe('auditHeaders', () => {
    it('flags missing security headers', () => {
      const headers: Record<string, string> = {
        'content-type': 'text/html',
      }
      const result = auditHeaders('https://example.com', headers)
      const missing = result.filter((r) => r.status === 'MISSING')
      expect(missing.length).toBeGreaterThan(3)
    })

    it('passes when all security headers present', () => {
      const headers: Record<string, string> = {
        'strict-transport-security': 'max-age=31536000; includeSubDomains; preload',
        'content-security-policy': "default-src 'self'",
        'x-content-type-options': 'nosniff',
        'x-frame-options': 'DENY',
        'referrer-policy': 'strict-origin-when-cross-origin',
        'permissions-policy': 'geolocation=()',
        'x-xss-protection': '0',
      }
      const result = auditHeaders('https://example.com', headers)
      const present = result.filter((r) => r.status === 'PRESENT')
      expect(present.length).toBeGreaterThanOrEqual(6)
    })

    it('warns on weak CSP with unsafe-inline', () => {
      const headers: Record<string, string> = {
        'content-security-policy': "default-src 'self' 'unsafe-inline'",
      }
      const result = auditHeaders('https://example.com', headers)
      const csp = result.find((r) => r.header === 'Content-Security-Policy')
      expect(csp?.status).toBe('WEAK')
    })

    it('warns on weak CSP with unsafe-eval', () => {
      const headers: Record<string, string> = {
        'content-security-policy': "default-src 'self' 'unsafe-eval'",
      }
      const result = auditHeaders('https://example.com', headers)
      const csp = result.find((r) => r.header === 'Content-Security-Policy')
      expect(csp?.status).toBe('WEAK')
    })

    it('warns on weak HSTS with short max-age', () => {
      const headers: Record<string, string> = {
        'strict-transport-security': 'max-age=3600',
      }
      const result = auditHeaders('https://example.com', headers)
      const hsts = result.find((r) => r.header === 'Strict-Transport-Security')
      expect(hsts?.status).toBe('WEAK')
    })

    it('passes HSTS with sufficient max-age', () => {
      const headers: Record<string, string> = {
        'strict-transport-security': 'max-age=31536000',
      }
      const result = auditHeaders('https://example.com', headers)
      const hsts = result.find((r) => r.header === 'Strict-Transport-Security')
      expect(hsts?.status).toBe('PRESENT')
    })

    it('returns url in every result', () => {
      const result = auditHeaders('https://test.dev', {})
      for (const r of result) {
        expect(r.url).toBe('https://test.dev')
      }
    })

    it('checks Cross-Origin-Opener-Policy header', () => {
      const result = auditHeaders('https://example.com', {})
      const coop = result.find(
        (r) => r.header === 'Cross-Origin-Opener-Policy',
      )
      expect(coop).toBeDefined()
      expect(coop!.status).toBe('MISSING')
      expect(coop!.severity).toBe('medium')
    })

    it('checks Cross-Origin-Resource-Policy header', () => {
      const result = auditHeaders('https://example.com', {})
      const corp = result.find(
        (r) => r.header === 'Cross-Origin-Resource-Policy',
      )
      expect(corp).toBeDefined()
      expect(corp!.status).toBe('MISSING')
      expect(corp!.severity).toBe('medium')
    })

    it('checks Cross-Origin-Embedder-Policy header', () => {
      const result = auditHeaders('https://example.com', {})
      const coep = result.find(
        (r) => r.header === 'Cross-Origin-Embedder-Policy',
      )
      expect(coep).toBeDefined()
      expect(coep!.status).toBe('MISSING')
      expect(coep!.severity).toBe('low')
    })

    it('marks Cross-Origin headers as PRESENT when set', () => {
      const headers: Record<string, string> = {
        'cross-origin-opener-policy': 'same-origin',
        'cross-origin-resource-policy': 'same-origin',
        'cross-origin-embedder-policy': 'require-corp',
      }
      const result = auditHeaders('https://example.com', headers)
      const coop = result.find(
        (r) => r.header === 'Cross-Origin-Opener-Policy',
      )
      const corp = result.find(
        (r) => r.header === 'Cross-Origin-Resource-Policy',
      )
      const coep = result.find(
        (r) => r.header === 'Cross-Origin-Embedder-Policy',
      )
      expect(coop!.status).toBe('PRESENT')
      expect(corp!.status).toBe('PRESENT')
      expect(coep!.status).toBe('PRESENT')
    })
  })
})
