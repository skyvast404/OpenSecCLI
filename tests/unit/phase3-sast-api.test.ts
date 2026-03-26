import { describe, it, expect } from 'vitest'
import { parseGosecOutput } from '../../src/adapters/scan/gosec-scan.js'
import { parseBanditOutput } from '../../src/adapters/scan/bandit-scan.js'
import { parseGraphqlCopOutput } from '../../src/adapters/vuln/graphql-audit.js'
import { analyzeJWT } from '../../src/adapters/pentest/jwt-test.js'

describe('scan/gosec-scan', () => {
  it('parses gosec JSON output with issues', () => {
    const output = JSON.stringify({
      Issues: [
        {
          severity: 'HIGH',
          confidence: 'HIGH',
          cwe: { id: '327' },
          rule_id: 'G501',
          details: 'Blocklisted import crypto/md5: weak cryptographic primitive',
          file: '/app/hash.go',
          line: '12',
          column: '2',
        },
        {
          severity: 'MEDIUM',
          confidence: 'HIGH',
          cwe: { id: '78' },
          rule_id: 'G204',
          details: 'Subprocess launched with variable',
          file: '/app/cmd.go',
          line: '45',
          column: '8',
        },
      ],
    })

    const rows = parseGosecOutput(output)
    expect(rows).toHaveLength(2)
    expect(rows[0]).toEqual({
      rule_id: 'G501',
      severity: 'HIGH',
      confidence: 'HIGH',
      file: '/app/hash.go',
      line: '12',
      message: 'Blocklisted import crypto/md5: weak cryptographic primitive',
      cwe: '327',
    })
    expect(rows[1]).toMatchObject({
      rule_id: 'G204',
      severity: 'MEDIUM',
      file: '/app/cmd.go',
      line: '45',
    })
  })

  it('returns empty array for invalid JSON', () => {
    expect(parseGosecOutput('not json')).toEqual([])
  })

  it('handles output with no issues', () => {
    expect(parseGosecOutput(JSON.stringify({ Issues: [] }))).toEqual([])
    expect(parseGosecOutput(JSON.stringify({}))).toEqual([])
  })
})

describe('scan/bandit-scan', () => {
  it('parses bandit JSON output with results', () => {
    const output = JSON.stringify({
      results: [
        {
          test_id: 'B101',
          severity: 'LOW',
          confidence: 'HIGH',
          filename: '/app/test_utils.py',
          line_number: 23,
          issue_text: 'Use of assert detected.',
          issue_cwe: { id: 703 },
        },
        {
          test_id: 'B608',
          severity: 'MEDIUM',
          confidence: 'MEDIUM',
          filename: '/app/db.py',
          line_number: 88,
          issue_text: 'Possible SQL injection vector through string-based query',
          issue_cwe: { id: 89 },
        },
      ],
    })

    const rows = parseBanditOutput(output)
    expect(rows).toHaveLength(2)
    expect(rows[0]).toEqual({
      test_id: 'B101',
      severity: 'LOW',
      confidence: 'HIGH',
      file: '/app/test_utils.py',
      line: 23,
      message: 'Use of assert detected.',
      cwe: '703',
    })
    expect(rows[1]).toMatchObject({
      test_id: 'B608',
      severity: 'MEDIUM',
      file: '/app/db.py',
      cwe: '89',
    })
  })

  it('returns empty array for invalid JSON', () => {
    expect(parseBanditOutput('bandit output error')).toEqual([])
  })

  it('handles output with no results', () => {
    expect(parseBanditOutput(JSON.stringify({ results: [] }))).toEqual([])
    expect(parseBanditOutput(JSON.stringify({}))).toEqual([])
  })
})

describe('vuln/graphql-audit', () => {
  it('parses graphql-cop JSON output with findings', () => {
    const output = JSON.stringify([
      {
        title: 'Introspection Enabled',
        severity: 'HIGH',
        description: 'GraphQL introspection is enabled, exposing the entire schema',
        impact: 'Attackers can discover all queries, mutations, and types',
      },
      {
        title: 'Field Suggestions Enabled',
        severity: 'LOW',
        description: 'GraphQL field suggestions are enabled',
        impact: 'Schema information leakage through error messages',
      },
    ])

    const rows = parseGraphqlCopOutput(output)
    expect(rows).toHaveLength(2)
    expect(rows[0]).toEqual({
      title: 'Introspection Enabled',
      severity: 'HIGH',
      description: 'GraphQL introspection is enabled, exposing the entire schema',
      impact: 'Attackers can discover all queries, mutations, and types',
    })
    expect(rows[1]).toMatchObject({
      title: 'Field Suggestions Enabled',
      severity: 'LOW',
    })
  })

  it('returns empty array for invalid JSON', () => {
    expect(parseGraphqlCopOutput('error output')).toEqual([])
  })

  it('handles empty array output', () => {
    expect(parseGraphqlCopOutput('[]')).toEqual([])
  })

  it('handles non-array JSON', () => {
    expect(parseGraphqlCopOutput('{"error": "not found"}')).toEqual([])
  })
})

describe('pentest/jwt-test', () => {
  it('detects alg:none and missing claims in test token', () => {
    // Header: {"alg":"none","typ":"JWT"}, Payload: {"sub":"1234567890","name":"John Doe"}
    const token = 'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.'
    const checks = analyzeJWT(token)

    const algNone = checks.find((c) => c.check === 'Algorithm None')
    expect(algNone).toBeDefined()
    expect(algNone!.status).toBe('FAIL')
    expect(algNone!.severity).toBe('CRITICAL')

    const expCheck = checks.find((c) => c.check === 'Expiration Claim')
    expect(expCheck).toBeDefined()
    expect(expCheck!.status).toBe('FAIL')
    expect(expCheck!.severity).toBe('MEDIUM')

    const audCheck = checks.find((c) => c.check === 'Audience Claim')
    expect(audCheck).toBeDefined()
    expect(audCheck!.status).toBe('FAIL')
    expect(audCheck!.severity).toBe('LOW')

    const issCheck = checks.find((c) => c.check === 'Issuer Claim')
    expect(issCheck).toBeDefined()
    expect(issCheck!.status).toBe('FAIL')
    expect(issCheck!.severity).toBe('LOW')
  })

  it('detects HS256 algorithm confusion risk', () => {
    // Header: {"alg":"HS256","typ":"JWT"}, Payload: {"sub":"user","exp":9999999999,"aud":"app","iss":"auth"}
    const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url')
    const payload = Buffer.from(JSON.stringify({
      sub: 'user',
      exp: 9999999999,
      aud: 'app',
      iss: 'auth',
    })).toString('base64url')
    const token = `${header}.${payload}.fakesig`

    const checks = analyzeJWT(token)

    const algConfusion = checks.find((c) => c.check === 'Algorithm Confusion')
    expect(algConfusion).toBeDefined()
    expect(algConfusion!.status).toBe('FAIL')
    expect(algConfusion!.severity).toBe('HIGH')

    const algNone = checks.find((c) => c.check === 'Algorithm None')
    expect(algNone!.status).toBe('PASS')

    const expCheck = checks.find((c) => c.check === 'Expiration Claim')
    expect(expCheck!.status).toBe('PASS')

    const audCheck = checks.find((c) => c.check === 'Audience Claim')
    expect(audCheck!.status).toBe('PASS')

    const issCheck = checks.find((c) => c.check === 'Issuer Claim')
    expect(issCheck!.status).toBe('PASS')
  })

  it('detects path traversal in kid header', () => {
    const header = Buffer.from(JSON.stringify({
      alg: 'RS256',
      typ: 'JWT',
      kid: '../../../etc/passwd',
    })).toString('base64url')
    const payload = Buffer.from(JSON.stringify({
      sub: 'admin',
      exp: 9999999999,
      aud: 'app',
      iss: 'auth',
    })).toString('base64url')
    const token = `${header}.${payload}.sig`

    const checks = analyzeJWT(token)

    const kidCheck = checks.find((c) => c.check === 'Key ID Traversal')
    expect(kidCheck).toBeDefined()
    expect(kidCheck!.status).toBe('FAIL')
    expect(kidCheck!.severity).toBe('HIGH')
    expect(kidCheck!.detail).toContain('../../../etc/passwd')
  })

  it('rejects invalid token format', () => {
    const checks = analyzeJWT('not-a-jwt')
    expect(checks).toHaveLength(1)
    expect(checks[0].status).toBe('FAIL')
    expect(checks[0].severity).toBe('CRITICAL')
    expect(checks[0].check).toBe('Token Format')
  })

  it('detects expired token', () => {
    const header = Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'JWT' })).toString('base64url')
    const payload = Buffer.from(JSON.stringify({
      sub: 'user',
      exp: 1000000000,
      aud: 'app',
      iss: 'auth',
    })).toString('base64url')
    const token = `${header}.${payload}.sig`

    const checks = analyzeJWT(token)
    const expCheck = checks.find((c) => c.check === 'Expiration Claim')
    expect(expCheck).toBeDefined()
    expect(expCheck!.status).toBe('FAIL')
    expect(expCheck!.severity).toBe('MEDIUM')
    expect(expCheck!.detail).toContain('expired')
  })
})
