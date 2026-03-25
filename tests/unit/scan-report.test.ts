import { describe, it, expect } from 'vitest'
import {
  buildJsonReport,
  buildSarifReport,
  buildMarkdownReport,
  severityToSarif,
} from '../../src/adapters/scan/report.js'
import type { RawFinding } from '../../src/adapters/scan/types.js'

const SAMPLE_FINDINGS: RawFinding[] = [
  {
    rule_id: 'sql-injection',
    severity: 'high',
    message: 'SQL injection via string concat',
    file_path: 'src/search.py',
    start_line: 45,
    cwe: 'CWE-89',
    tools_used: ['semgrep'],
  },
  {
    rule_id: 'hardcoded-secret',
    severity: 'critical',
    message: 'API key in source',
    file_path: 'config.py',
    start_line: 10,
    cwe: 'CWE-798',
    tools_used: ['gitleaks'],
  },
]

describe('buildJsonReport', () => {
  it('produces valid JSON report structure', () => {
    const report = buildJsonReport(SAMPLE_FINDINGS, '/repo', 5000)
    expect(report.target).toBe('/repo')
    expect(report.duration_ms).toBe(5000)
    expect(report.findings).toHaveLength(2)
    expect(report.summary.total).toBe(2)
    expect(report.summary.critical).toBe(1)
    expect(report.summary.high).toBe(1)
  })
})

describe('buildSarifReport', () => {
  it('produces valid SARIF 2.1.0 structure', () => {
    const sarif = buildSarifReport(SAMPLE_FINDINGS)
    expect(sarif.$schema).toContain('sarif')
    expect(sarif.version).toBe('2.1.0')
    expect(sarif.runs).toHaveLength(1)
    expect(sarif.runs[0].results).toHaveLength(2)
    expect(sarif.runs[0].tool.driver.name).toBe('OpenSecCLI')
  })

  it('maps severity correctly', () => {
    expect(severityToSarif('critical')).toBe('error')
    expect(severityToSarif('high')).toBe('error')
    expect(severityToSarif('medium')).toBe('warning')
    expect(severityToSarif('low')).toBe('note')
    expect(severityToSarif('info')).toBe('note')
  })
})

describe('buildMarkdownReport', () => {
  it('produces markdown with severity sections', () => {
    const md = buildMarkdownReport(SAMPLE_FINDINGS, '/repo', 5000)
    expect(md).toContain('# Security Scan Report')
    expect(md).toContain('CWE-89')
    expect(md).toContain('CWE-798')
    expect(md).toContain('Critical')
    expect(md).toContain('High')
    expect(md).toContain('2 findings')
  })

  it('handles empty findings', () => {
    const md = buildMarkdownReport([], '/repo', 1000)
    expect(md).toContain('No security findings')
  })
})
