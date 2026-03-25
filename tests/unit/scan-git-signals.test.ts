import { describe, it, expect } from 'vitest'
import { extractSignals, SECURITY_KEYWORDS } from '../../src/adapters/scan/git-signals.js'

describe('extractSignals', () => {
  it('matches security-relevant commit messages', () => {
    const logs = [
      { hash: 'aaa', message: 'fix: prevent SQL injection in search', files: ['src/search.py'] },
      { hash: 'bbb', message: 'feat: add user profile page', files: ['src/profile.py'] },
      { hash: 'ccc', message: 'fix: escape XSS in template rendering', files: ['src/render.py'] },
      { hash: 'ddd', message: 'chore: update deps', files: ['package.json'] },
    ]
    const signals = extractSignals(logs)
    expect(signals).toHaveLength(2)
    expect(signals[0].commit).toBe('aaa')
    expect(signals[1].commit).toBe('ccc')
  })

  it('extracts matched keywords', () => {
    const logs = [
      { hash: 'aaa', message: 'fix: sanitize input to prevent injection', files: ['src/input.py'] },
    ]
    const signals = extractSignals(logs)
    expect(signals[0].keywords).toContain('sanitize')
    expect(signals[0].keywords).toContain('inject')
  })

  it('respects max signals limit', () => {
    const logs = Array.from({ length: 30 }, (_, i) => ({
      hash: `h${i}`,
      message: `fix: vulnerability CVE-${i}`,
      files: [`src/file${i}.py`],
    }))
    const signals = extractSignals(logs, 20)
    expect(signals).toHaveLength(20)
  })

  it('returns empty for no security commits', () => {
    const logs = [
      { hash: 'aaa', message: 'feat: add pagination', files: ['src/list.py'] },
    ]
    expect(extractSignals(logs)).toHaveLength(0)
  })
})

describe('SECURITY_KEYWORDS', () => {
  it('includes core keywords', () => {
    expect(SECURITY_KEYWORDS).toContain('vuln')
    expect(SECURITY_KEYWORDS).toContain('xss')
    expect(SECURITY_KEYWORDS).toContain('inject')
    expect(SECURITY_KEYWORDS).toContain('cve')
  })
})
