import { describe, it, expect } from 'vitest'
import { buildScanSummary } from '../../src/adapters/scan/full.js'
import type { RawFinding } from '../../src/adapters/scan/types.js'

describe('buildScanSummary', () => {
  it('counts findings by severity', () => {
    const findings: RawFinding[] = [
      { rule_id: 'a', severity: 'critical', message: '', file_path: '', start_line: 0, cwe: '', tools_used: [] },
      { rule_id: 'b', severity: 'high', message: '', file_path: '', start_line: 0, cwe: '', tools_used: [] },
      { rule_id: 'c', severity: 'high', message: '', file_path: '', start_line: 0, cwe: '', tools_used: [] },
      { rule_id: 'd', severity: 'medium', message: '', file_path: '', start_line: 0, cwe: '', tools_used: [] },
    ]
    const summary = buildScanSummary(findings, 5000)
    expect(summary.total).toBe(4)
    expect(summary.critical).toBe(1)
    expect(summary.high).toBe(2)
    expect(summary.medium).toBe(1)
    expect(summary.low).toBe(0)
    expect(summary.duration_ms).toBe(5000)
  })

  it('handles empty findings', () => {
    const summary = buildScanSummary([], 1000)
    expect(summary.total).toBe(0)
  })
})
