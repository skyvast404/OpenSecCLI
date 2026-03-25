import { describe, it, expect } from 'vitest'
import {
  parseSemgrepOutput,
  parseGitleaksOutput,
  parseNpmAuditOutput,
  parsePipAuditOutput,
  normalizeFindings,
  deduplicateFindings,
} from '../../src/adapters/scan/analyze.js'

describe('parseSemgrepOutput', () => {
  it('parses semgrep JSON results', () => {
    const output = {
      results: [
        {
          check_id: 'python.lang.security.audit.dangerous-system-call',
          path: 'src/cmd.py',
          start: { line: 12 },
          extra: {
            message: 'Detected dangerous system call',
            severity: 'ERROR',
            metadata: { cwe: ['CWE-78: OS Command Injection'] },
          },
        },
      ],
    }
    const findings = parseSemgrepOutput(output)
    expect(findings).toHaveLength(1)
    expect(findings[0]).toMatchObject({
      rule_id: 'python.lang.security.audit.dangerous-system-call',
      file_path: 'src/cmd.py',
      start_line: 12,
      severity: 'high',
      cwe: 'CWE-78',
      tools_used: ['semgrep'],
    })
  })
})

describe('parseGitleaksOutput', () => {
  it('parses gitleaks JSON results', () => {
    const output = [
      {
        RuleID: 'generic-api-key',
        File: 'config.py',
        StartLine: 5,
        Description: 'Generic API Key',
      },
    ]
    const findings = parseGitleaksOutput(output)
    expect(findings).toHaveLength(1)
    expect(findings[0]).toMatchObject({
      rule_id: 'generic-api-key',
      cwe: 'CWE-798',
      tools_used: ['gitleaks'],
    })
  })
})

describe('parseNpmAuditOutput', () => {
  it('parses npm audit JSON results', () => {
    const output = {
      vulnerabilities: {
        lodash: {
          name: 'lodash',
          severity: 'high',
          title: 'Prototype Pollution',
          via: [],
        },
      },
    }
    const findings = parseNpmAuditOutput(output)
    expect(findings).toHaveLength(1)
    expect(findings[0]).toMatchObject({
      rule_id: 'npm-lodash',
      severity: 'high',
      file_path: 'package.json',
      tools_used: ['npm-audit'],
    })
  })

  it('maps moderate to medium severity', () => {
    const output = {
      vulnerabilities: {
        foo: { name: 'foo', severity: 'moderate', title: 'Issue' },
      },
    }
    const findings = parseNpmAuditOutput(output)
    expect(findings[0].severity).toBe('medium')
  })
})

describe('parsePipAuditOutput', () => {
  it('parses pip-audit JSON results', () => {
    const output = [
      {
        name: 'flask',
        version: '1.0',
        id: 'PYSEC-2021-123',
        description: 'Vulnerable to XSS',
      },
    ]
    const findings = parsePipAuditOutput(output)
    expect(findings).toHaveLength(1)
    expect(findings[0]).toMatchObject({
      rule_id: 'pip-flask-PYSEC-2021-123',
      severity: 'medium',
      file_path: 'requirements.txt',
      tools_used: ['pip-audit'],
    })
  })
})

describe('normalizeFindings', () => {
  it('fills default values for missing fields', () => {
    const findings = [
      {
        rule_id: 'test',
        severity: undefined as unknown as 'high',
        message: 'msg',
        file_path: 'f.py',
        start_line: 1,
        cwe: undefined as unknown as string,
        tools_used: undefined as unknown as string[],
      },
    ]
    const normalized = normalizeFindings(findings)
    expect(normalized[0].severity).toBe('medium')
    expect(normalized[0].cwe).toBe('')
    expect(normalized[0].tools_used).toEqual([])
  })
})

describe('deduplicateFindings', () => {
  it('merges findings with same file:line:cwe', () => {
    const findings = [
      {
        rule_id: 'sqli-1',
        severity: 'high' as const,
        message: 'SQL injection',
        file_path: 'a.py',
        start_line: 10,
        cwe: 'CWE-89',
        tools_used: ['semgrep'],
      },
      {
        rule_id: 'sqli-2',
        severity: 'high' as const,
        message: 'SQL injection variant',
        file_path: 'a.py',
        start_line: 10,
        cwe: 'CWE-89',
        tools_used: ['semantic'],
      },
    ]
    const deduped = deduplicateFindings(findings)
    expect(deduped).toHaveLength(1)
    expect(deduped[0].tools_used).toContain('semgrep')
    expect(deduped[0].tools_used).toContain('semantic')
  })

  it('keeps findings with different keys', () => {
    const findings = [
      {
        rule_id: 'sqli',
        severity: 'high' as const,
        message: 'SQL injection',
        file_path: 'a.py',
        start_line: 10,
        cwe: 'CWE-89',
        tools_used: ['semgrep'],
      },
      {
        rule_id: 'xss',
        severity: 'medium' as const,
        message: 'XSS',
        file_path: 'b.py',
        start_line: 20,
        cwe: 'CWE-79',
        tools_used: ['semgrep'],
      },
    ]
    const deduped = deduplicateFindings(findings)
    expect(deduped).toHaveLength(2)
  })
})
