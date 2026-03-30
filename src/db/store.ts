/**
 * Finding database — stores scan results with history for diff/trend analysis.
 * Uses Node 22+ built-in SQLite (node:sqlite).
 * DB location: ~/.openseccli/findings.db
 */

import { DatabaseSync } from 'node:sqlite'
import type { StatementResultingChanges } from 'node:sqlite'
import { join } from 'node:path'
import { homedir } from 'node:os'
import { mkdirSync, existsSync } from 'node:fs'

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

// Re-export the SQLite input type for convenience
type SqlParam = null | number | bigint | string

export interface Finding {
  id: number
  fingerprint: string
  target: string
  source: string
  severity: string
  title: string
  detail: string | null
  file_path: string | null
  line: number | null
  cwe: string | null
  first_seen_at: string
  last_seen_at: string
  resolved_at: string | null
  dismissed: number
  dismiss_reason: string | null
  scan_count: number
  raw_json: string | null
}

// ---------------------------------------------------------------------------
// Database lifecycle
// ---------------------------------------------------------------------------

const DB_DIR = join(homedir(), '.openseccli')
const DB_PATH = join(DB_DIR, 'findings.db')

let db: DatabaseSync | null = null

function initSchema(instance: DatabaseSync): void {
  instance.exec(`
    CREATE TABLE IF NOT EXISTS findings (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      fingerprint TEXT NOT NULL,
      target TEXT NOT NULL,
      source TEXT NOT NULL,
      severity TEXT NOT NULL DEFAULT 'info',
      title TEXT NOT NULL,
      detail TEXT,
      file_path TEXT,
      line INTEGER,
      cwe TEXT,
      first_seen_at TEXT NOT NULL DEFAULT (datetime('now')),
      last_seen_at TEXT NOT NULL DEFAULT (datetime('now')),
      resolved_at TEXT,
      dismissed INTEGER NOT NULL DEFAULT 0,
      dismiss_reason TEXT,
      scan_count INTEGER NOT NULL DEFAULT 1,
      raw_json TEXT
    );

    CREATE UNIQUE INDEX IF NOT EXISTS idx_fingerprint ON findings(fingerprint);
    CREATE INDEX IF NOT EXISTS idx_target ON findings(target);
    CREATE INDEX IF NOT EXISTS idx_severity ON findings(severity);
    CREATE INDEX IF NOT EXISTS idx_last_seen ON findings(last_seen_at);

    CREATE TABLE IF NOT EXISTS scans (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      target TEXT NOT NULL,
      command TEXT NOT NULL,
      findings_count INTEGER NOT NULL DEFAULT 0,
      duration_ms INTEGER,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
  `)
}

/** Initialise (or re-initialise) the database at a custom path — useful for tests. */
export function initDb(path?: string): DatabaseSync {
  if (db) {
    db.close()
    db = null
  }
  const resolvedPath = path ?? DB_PATH
  if (resolvedPath !== ':memory:' && !existsSync(DB_DIR)) {
    mkdirSync(DB_DIR, { recursive: true })
  }
  db = new DatabaseSync(resolvedPath)
  initSchema(db)
  return db
}

export function getDb(): DatabaseSync {
  if (db) return db
  return initDb()
}

export function closeDb(): void {
  if (db) {
    db.close()
    db = null
  }
}

// ---------------------------------------------------------------------------
// Fingerprint
// ---------------------------------------------------------------------------

/** Generate a stable fingerprint for deduplication. */
export function fingerprint(finding: {
  source: string
  title: string
  file_path?: string
  line?: number
  cwe?: string
  [key: string]: unknown
}): string {
  const parts = [
    finding.source,
    finding.title,
    finding.file_path ?? '',
    String(finding.line ?? ''),
    finding.cwe ?? '',
  ]
  const str = parts.join('|')
  return Buffer.from(str).toString('base64url').slice(0, 32)
}

// ---------------------------------------------------------------------------
// Upsert
// ---------------------------------------------------------------------------

/** Upsert a finding — insert new or bump last_seen_at + scan_count. */
export function upsertFinding(
  target: string,
  finding: {
    source: string
    severity: string
    title: string
    detail?: string
    file_path?: string
    line?: number
    cwe?: string
    raw?: unknown
  },
): void {
  const instance = getDb()
  const fp = fingerprint({ ...finding })

  const existing = instance
    .prepare('SELECT id, scan_count FROM findings WHERE fingerprint = ?')
    .get(fp)

  if (existing) {
    instance
      .prepare(
        `UPDATE findings
         SET last_seen_at = datetime('now'),
             scan_count = scan_count + 1,
             resolved_at = NULL,
             severity = ?,
             detail = ?
         WHERE fingerprint = ?`,
      )
      .run(finding.severity, finding.detail ?? '', fp)
  } else {
    instance
      .prepare(
        `INSERT INTO findings
           (fingerprint, target, source, severity, title, detail, file_path, line, cwe, raw_json)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        fp,
        target,
        finding.source,
        finding.severity,
        finding.title,
        finding.detail ?? '',
        finding.file_path ?? '',
        finding.line ?? 0,
        finding.cwe ?? '',
        JSON.stringify(finding.raw ?? null),
      )
  }
}

// ---------------------------------------------------------------------------
// Scan history
// ---------------------------------------------------------------------------

/** Record a completed scan run. */
export function recordScan(
  target: string,
  command: string,
  findingsCount: number,
  durationMs: number,
): void {
  const instance = getDb()
  instance
    .prepare(
      'INSERT INTO scans (target, command, findings_count, duration_ms) VALUES (?, ?, ?, ?)',
    )
    .run(target, command, findingsCount, durationMs)
}

// ---------------------------------------------------------------------------
// Resolution
// ---------------------------------------------------------------------------

/** Mark findings not seen in latest scan as resolved. Returns count of resolved rows. */
export function markResolved(
  target: string,
  source: string,
  seenFingerprints: string[],
): number {
  const instance = getDb()
  if (seenFingerprints.length === 0) return 0

  const placeholders = seenFingerprints.map(() => '?').join(',')
  const result: StatementResultingChanges = instance
    .prepare(
      `UPDATE findings
       SET resolved_at = datetime('now')
       WHERE target = ?
         AND source = ?
         AND fingerprint NOT IN (${placeholders})
         AND resolved_at IS NULL
         AND dismissed = 0`,
    )
    .run(target, source, ...seenFingerprints)

  return Number(result.changes)
}

// ---------------------------------------------------------------------------
// Dismiss
// ---------------------------------------------------------------------------

/** Dismiss a finding by fingerprint. Returns true if a row was updated. */
export function dismissFinding(
  fingerprintId: string,
  reason: string,
): boolean {
  const instance = getDb()
  const result: StatementResultingChanges = instance
    .prepare(
      'UPDATE findings SET dismissed = 1, dismiss_reason = ? WHERE fingerprint = ?',
    )
    .run(reason, fingerprintId)
  return Number(result.changes) > 0
}

// ---------------------------------------------------------------------------
// Query
// ---------------------------------------------------------------------------

/** Query findings with optional filters. */
export function queryFindings(opts: {
  target?: string
  severity?: string
  since?: string // ISO date string
  resolved?: boolean
  dismissed?: boolean
  limit?: number
}): Finding[] {
  const instance = getDb()
  const conditions: string[] = []
  const params: SqlParam[] = []

  if (opts.target) {
    conditions.push('target = ?')
    params.push(opts.target)
  }
  if (opts.severity) {
    conditions.push('severity = ?')
    params.push(opts.severity)
  }
  if (opts.since) {
    conditions.push('last_seen_at >= ?')
    params.push(opts.since)
  }
  if (opts.resolved === true) {
    conditions.push('resolved_at IS NOT NULL')
  }
  if (opts.resolved === false) {
    conditions.push('resolved_at IS NULL')
  }
  if (opts.dismissed === false) {
    conditions.push('dismissed = 0')
  }

  const where =
    conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : ''
  const limit = opts.limit ? `LIMIT ${opts.limit}` : ''

  return instance
    .prepare(
      `SELECT * FROM findings ${where} ORDER BY severity, last_seen_at DESC ${limit}`,
    )
    .all(...params) as unknown as Finding[]
}

// ---------------------------------------------------------------------------
// Diff
// ---------------------------------------------------------------------------

/** Get diff since a date — new findings, resolved, and regressed. */
export function getDiff(
  target: string,
  sinceDate: string,
): {
  new_findings: Finding[]
  resolved: Finding[]
  regressed: Finding[]
} {
  const instance = getDb()

  const new_findings = instance
    .prepare(
      `SELECT * FROM findings
       WHERE target = ? AND first_seen_at >= ? AND dismissed = 0
       ORDER BY severity`,
    )
    .all(target, sinceDate) as unknown as Finding[]

  const resolved = instance
    .prepare(
      `SELECT * FROM findings
       WHERE target = ? AND resolved_at >= ? AND dismissed = 0
       ORDER BY severity`,
    )
    .all(target, sinceDate) as unknown as Finding[]

  const regressed = instance
    .prepare(
      `SELECT * FROM findings
       WHERE target = ?
         AND resolved_at IS NULL
         AND dismissed = 0
         AND first_seen_at < ?
         AND last_seen_at >= ?
         AND scan_count > 1
       ORDER BY severity`,
    )
    .all(target, sinceDate, sinceDate) as unknown as Finding[]

  return { new_findings, resolved, regressed }
}

// ---------------------------------------------------------------------------
// Trend
// ---------------------------------------------------------------------------

/** Get daily scan trend data for the last N days. */
export function getTrend(
  target: string,
  days: number,
): Record<string, unknown>[] {
  const instance = getDb()
  return instance
    .prepare(
      `SELECT
         date(created_at) as date,
         SUM(findings_count) as total_findings,
         COUNT(*) as scan_count
       FROM scans
       WHERE target = ? AND created_at >= datetime('now', ?)
       GROUP BY date(created_at)
       ORDER BY date`,
    )
    .all(target, `-${days} days`) as Record<string, unknown>[]
}
