import { describe, it, expect } from 'vitest'
import type {
  EntryPoint, EntryPointKind, GitSignal,
  RawFinding, ScanReport, PhaseMetric,
} from '../../src/adapters/scan/types.js'

describe('scan types', () => {
  it('EntryPoint satisfies shape', () => {
    const ep: EntryPoint = {
      file: 'src/api.py',
      line: 42,
      kind: 'http_route',
      method: 'POST',
      pattern: '/api/users',
      framework: 'flask',
    }
    expect(ep.kind).toBe('http_route')
    expect(ep.file).toBe('src/api.py')
  })

  it('RawFinding satisfies shape', () => {
    const f: RawFinding = {
      rule_id: 'sql-injection',
      severity: 'high',
      message: 'SQL injection via string concat',
      file_path: 'src/search.py',
      start_line: 45,
      cwe: 'CWE-89',
      tools_used: ['semgrep'],
    }
    expect(f.cwe).toBe('CWE-89')
  })

  it('GitSignal satisfies shape', () => {
    const sig: GitSignal = {
      commit: 'abc1234',
      message: 'fix: sanitize input',
      files: ['src/search.py'],
      diff_summary: 'Added parameterized query',
    }
    expect(sig.files).toHaveLength(1)
  })
})
