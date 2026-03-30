import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import {
  initDb,
  closeDb,
  fingerprint,
  upsertFinding,
  queryFindings,
  dismissFinding,
  markResolved,
  recordScan,
  getDiff,
  getTrend,
  getDb,
} from '../../src/db/store.js'

describe('Finding Database (store)', () => {
  beforeEach(() => {
    initDb(':memory:')
  })

  afterEach(() => {
    closeDb()
  })

  // -----------------------------------------------------------------------
  // fingerprint
  // -----------------------------------------------------------------------

  it('produces a stable fingerprint for the same input', () => {
    const a = fingerprint({ source: 'semgrep', title: 'SQL injection', file_path: 'app.ts', line: 42 })
    const b = fingerprint({ source: 'semgrep', title: 'SQL injection', file_path: 'app.ts', line: 42 })
    expect(a).toBe(b)
    expect(a.length).toBeLessThanOrEqual(32)
  })

  it('produces different fingerprints for different inputs', () => {
    const a = fingerprint({ source: 'semgrep', title: 'SQL injection' })
    const b = fingerprint({ source: 'semgrep', title: 'XSS' })
    const c = fingerprint({ source: 'trivy', title: 'SQL injection' })
    expect(a).not.toBe(b)
    expect(a).not.toBe(c)
  })

  // -----------------------------------------------------------------------
  // upsertFinding — insert
  // -----------------------------------------------------------------------

  it('inserts a new finding and retrieves it via queryFindings', () => {
    upsertFinding('example.com', {
      source: 'nuclei',
      severity: 'high',
      title: 'Open redirect',
      detail: 'Redirect via Location header',
      file_path: '/login',
      cwe: 'CWE-601',
      raw: { id: 'nuclei:open-redirect' },
    })

    const rows = queryFindings({ target: 'example.com' })
    expect(rows).toHaveLength(1)
    expect(rows[0]).toMatchObject({
      target: 'example.com',
      source: 'nuclei',
      severity: 'high',
      title: 'Open redirect',
      cwe: 'CWE-601',
      scan_count: 1,
      dismissed: 0,
    })
    expect(rows[0].raw_json).toBe(JSON.stringify({ id: 'nuclei:open-redirect' }))
  })

  // -----------------------------------------------------------------------
  // upsertFinding — update (dedup)
  // -----------------------------------------------------------------------

  it('increments scan_count and clears resolved_at on duplicate upsert', () => {
    const finding = {
      source: 'trivy',
      severity: 'critical',
      title: 'CVE-2024-1234',
    }

    upsertFinding('myapp', finding)
    upsertFinding('myapp', finding)
    upsertFinding('myapp', finding)

    const rows = queryFindings({ target: 'myapp' })
    expect(rows).toHaveLength(1)
    expect(rows[0].scan_count).toBe(3)
  })

  // -----------------------------------------------------------------------
  // queryFindings — filters
  // -----------------------------------------------------------------------

  it('filters by severity and returns limited results', () => {
    upsertFinding('app', { source: 'semgrep', severity: 'high', title: 'A' })
    upsertFinding('app', { source: 'semgrep', severity: 'low', title: 'B' })
    upsertFinding('app', { source: 'semgrep', severity: 'high', title: 'C' })
    upsertFinding('app', { source: 'semgrep', severity: 'high', title: 'D' })

    const highOnly = queryFindings({ target: 'app', severity: 'high' })
    expect(highOnly).toHaveLength(3)

    const limited = queryFindings({ target: 'app', severity: 'high', limit: 2 })
    expect(limited).toHaveLength(2)
  })

  // -----------------------------------------------------------------------
  // dismissFinding
  // -----------------------------------------------------------------------

  it('dismisses a finding and filters it out with dismissed=false', () => {
    upsertFinding('app', { source: 'nuclei', severity: 'info', title: 'Banner grab' })

    const fp = fingerprint({ source: 'nuclei', title: 'Banner grab' })
    const ok = dismissFinding(fp, 'false positive')
    expect(ok).toBe(true)

    const all = queryFindings({ target: 'app' })
    expect(all).toHaveLength(1)
    expect(all[0].dismissed).toBe(1)
    expect(all[0].dismiss_reason).toBe('false positive')

    const active = queryFindings({ target: 'app', dismissed: false })
    expect(active).toHaveLength(0)
  })

  it('returns false when dismissing a non-existent fingerprint', () => {
    const ok = dismissFinding('nonexistent', 'reason')
    expect(ok).toBe(false)
  })

  // -----------------------------------------------------------------------
  // markResolved
  // -----------------------------------------------------------------------

  it('marks unseen findings as resolved', () => {
    upsertFinding('site', { source: 'nuclei', severity: 'medium', title: 'Finding A' })
    upsertFinding('site', { source: 'nuclei', severity: 'low', title: 'Finding B' })
    upsertFinding('site', { source: 'nuclei', severity: 'high', title: 'Finding C' })

    const fpA = fingerprint({ source: 'nuclei', title: 'Finding A' })
    // Only A was seen — B and C should be resolved
    const count = markResolved('site', 'nuclei', [fpA])
    expect(count).toBe(2)

    const unresolved = queryFindings({ target: 'site', resolved: false })
    expect(unresolved).toHaveLength(1)
    expect(unresolved[0].title).toBe('Finding A')

    const resolved = queryFindings({ target: 'site', resolved: true })
    expect(resolved).toHaveLength(2)
  })

  // -----------------------------------------------------------------------
  // getDiff
  // -----------------------------------------------------------------------

  it('returns new, resolved, and regressed findings in diff', () => {
    const db = getDb()

    // Insert an "old" finding manually with first_seen_at in the past
    db.exec(`
      INSERT INTO findings (fingerprint, target, source, severity, title, detail, file_path, line, cwe, raw_json, first_seen_at, last_seen_at, scan_count)
      VALUES ('old-fp', 'host', 'nuclei', 'medium', 'Old vuln', '', '', 0, '', 'null', '2025-01-01', '2026-03-29', 2)
    `)

    // Resolve an old finding
    db.exec(`
      INSERT INTO findings (fingerprint, target, source, severity, title, detail, file_path, line, cwe, raw_json, first_seen_at, resolved_at, last_seen_at, scan_count)
      VALUES ('resolved-fp', 'host', 'nuclei', 'low', 'Fixed vuln', '', '', 0, '', 'null', '2025-01-01', '2026-03-30', '2026-03-29', 1)
    `)

    // Insert a brand-new finding (first_seen_at = now)
    upsertFinding('host', { source: 'nuclei', severity: 'critical', title: 'New vuln' })

    const diff = getDiff('host', '2026-03-29')

    expect(diff.new_findings.length).toBeGreaterThanOrEqual(1)
    expect(diff.new_findings.some((f) => f.title === 'New vuln')).toBe(true)

    expect(diff.resolved.length).toBe(1)
    expect(diff.resolved[0].title).toBe('Fixed vuln')

    // "Old vuln" is regressed: first_seen < sinceDate, last_seen >= sinceDate, scan_count > 1, not resolved
    expect(diff.regressed.length).toBe(1)
    expect(diff.regressed[0].title).toBe('Old vuln')
  })

  // -----------------------------------------------------------------------
  // recordScan + getTrend
  // -----------------------------------------------------------------------

  it('records scans and retrieves trend data', () => {
    recordScan('example.com', 'nuclei -u example.com', 5, 1200)
    recordScan('example.com', 'nuclei -u example.com', 3, 800)

    const trend = getTrend('example.com', 1)
    expect(trend.length).toBeGreaterThanOrEqual(1)
    expect(Number(trend[0].total_findings)).toBe(8)
    expect(Number(trend[0].scan_count)).toBe(2)
  })

  // -----------------------------------------------------------------------
  // upsertFinding clears resolved_at on re-appearance
  // -----------------------------------------------------------------------

  it('clears resolved_at when a previously resolved finding reappears', () => {
    upsertFinding('site', { source: 'semgrep', severity: 'high', title: 'Bug' })

    const fp = fingerprint({ source: 'semgrep', title: 'Bug' })
    // Manually mark as resolved
    const db = getDb()
    db.prepare("UPDATE findings SET resolved_at = datetime('now') WHERE fingerprint = ?").run(fp)

    const resolvedRows = queryFindings({ target: 'site', resolved: true })
    expect(resolvedRows).toHaveLength(1)

    // Upsert again — should clear resolved_at
    upsertFinding('site', { source: 'semgrep', severity: 'high', title: 'Bug' })

    const afterRows = queryFindings({ target: 'site', resolved: false })
    expect(afterRows).toHaveLength(1)
    expect(afterRows[0].scan_count).toBe(2)
  })
})
