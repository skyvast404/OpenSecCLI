import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { mkdtempSync, rmSync, existsSync, readFileSync, readdirSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import {
  parseInterval,
  buildAlertPayload,
  saveWatchConfig,
  loadWatchConfig,
  listWatchConfigs,
  deleteWatchConfig,
  setWatchBaseDir,
} from '../../src/commands/watch.js'
import type { WatchConfig } from '../../src/commands/watch.js'

// ---------------------------------------------------------------------------
// Setup / Teardown
// ---------------------------------------------------------------------------

let tmpDir: string

beforeEach(() => {
  tmpDir = mkdtempSync(join(tmpdir(), 'opensec-watch-test-'))
  setWatchBaseDir(tmpDir)
})

afterEach(() => {
  setWatchBaseDir(null)
  rmSync(tmpDir, { recursive: true, force: true })
})

// ---------------------------------------------------------------------------
// parseInterval
// ---------------------------------------------------------------------------

describe('parseInterval', () => {
  it('parses minutes', () => {
    expect(parseInterval('30m')).toBe(30 * 60 * 1000)
  })

  it('parses hours', () => {
    expect(parseInterval('1h')).toBe(60 * 60 * 1000)
    expect(parseInterval('6h')).toBe(6 * 60 * 60 * 1000)
    expect(parseInterval('24h')).toBe(24 * 60 * 60 * 1000)
  })

  it('parses days', () => {
    expect(parseInterval('7d')).toBe(7 * 24 * 60 * 60 * 1000)
  })

  it('throws on invalid format', () => {
    expect(() => parseInterval('abc')).toThrow('Invalid interval format')
    expect(() => parseInterval('10x')).toThrow('Invalid interval format')
    expect(() => parseInterval('')).toThrow('Invalid interval format')
  })
})

// ---------------------------------------------------------------------------
// Watch config CRUD
// ---------------------------------------------------------------------------

describe('watch config CRUD', () => {
  const makeConfig = (overrides?: Partial<WatchConfig>): WatchConfig => ({
    id: 'test123',
    target: 'https://example.com',
    workflow: 'web-audit.yaml',
    interval: '1h',
    createdAt: '2026-03-30T10:00:00.000Z',
    runCount: 0,
    ...overrides,
  })

  it('saves and loads a watch config', () => {
    const config = makeConfig()
    saveWatchConfig(config)

    const loaded = loadWatchConfig('test123')
    expect(loaded).not.toBeNull()
    expect(loaded!.id).toBe('test123')
    expect(loaded!.target).toBe('https://example.com')
    expect(loaded!.workflow).toBe('web-audit.yaml')
    expect(loaded!.interval).toBe('1h')
    expect(loaded!.runCount).toBe(0)
  })

  it('returns null for non-existent config', () => {
    const loaded = loadWatchConfig('nonexistent')
    expect(loaded).toBeNull()
  })

  it('lists all watch configs', () => {
    saveWatchConfig(makeConfig({ id: 'w1', target: 'a.com' }))
    saveWatchConfig(makeConfig({ id: 'w2', target: 'b.com' }))
    saveWatchConfig(makeConfig({ id: 'w3', target: 'c.com' }))

    const configs = listWatchConfigs()
    expect(configs).toHaveLength(3)

    const ids = configs.map(c => c.id).sort()
    expect(ids).toEqual(['w1', 'w2', 'w3'])
  })

  it('deletes a watch config', () => {
    saveWatchConfig(makeConfig())
    expect(loadWatchConfig('test123')).not.toBeNull()

    const removed = deleteWatchConfig('test123')
    expect(removed).toBe(true)
    expect(loadWatchConfig('test123')).toBeNull()
  })

  it('returns false when deleting non-existent config', () => {
    const removed = deleteWatchConfig('ghost')
    expect(removed).toBe(false)
  })

  it('overwrites config on re-save (immutable update pattern)', () => {
    const original = makeConfig()
    saveWatchConfig(original)

    const updated: WatchConfig = {
      ...original,
      runCount: 5,
      lastRunAt: '2026-03-30T11:00:00.000Z',
      lastFindingsCount: 12,
    }
    saveWatchConfig(updated)

    const loaded = loadWatchConfig('test123')
    expect(loaded!.runCount).toBe(5)
    expect(loaded!.lastRunAt).toBe('2026-03-30T11:00:00.000Z')
    expect(loaded!.lastFindingsCount).toBe(12)
  })
})

// ---------------------------------------------------------------------------
// buildAlertPayload
// ---------------------------------------------------------------------------

describe('buildAlertPayload', () => {
  it('builds a valid alert payload', () => {
    const payload = buildAlertPayload({
      watchId: 'abc123',
      target: 'https://example.com',
      newFindings: 3,
      resolvedFindings: 1,
      totalFindings: 15,
      critical: 2,
      high: 5,
    })

    expect(payload.source).toBe('openseccli')
    expect(payload.watch_id).toBe('abc123')
    expect(payload.target).toBe('https://example.com')
    expect(payload.new_findings).toBe(3)
    expect(payload.resolved_findings).toBe(1)
    expect(payload.total_findings).toBe(15)
    expect(payload.critical).toBe(2)
    expect(payload.high).toBe(5)
    expect(payload.timestamp).toBeTruthy()
    expect(payload.summary).toContain('3 new findings detected')
    expect(payload.summary).toContain('2 critical')
  })

  it('produces "No changes" summary when nothing is new', () => {
    const payload = buildAlertPayload({
      watchId: 'x',
      target: 'example.com',
      newFindings: 0,
      resolvedFindings: 0,
      totalFindings: 10,
      critical: 0,
      high: 0,
    })

    expect(payload.summary).toBe('No changes')
  })

  it('uses singular "finding" for single new finding', () => {
    const payload = buildAlertPayload({
      watchId: 'y',
      target: 'example.com',
      newFindings: 1,
      resolvedFindings: 0,
      totalFindings: 1,
      critical: 0,
      high: 0,
    })

    expect(payload.summary).toContain('1 new finding detected')
    expect(payload.summary).not.toContain('findings detected')
  })

  it('includes resolved count in summary', () => {
    const payload = buildAlertPayload({
      watchId: 'z',
      target: 'example.com',
      newFindings: 0,
      resolvedFindings: 3,
      totalFindings: 5,
      critical: 0,
      high: 0,
    })

    expect(payload.summary).toContain('3 resolved')
  })

  it('includes ISO timestamp', () => {
    const before = new Date().toISOString()
    const payload = buildAlertPayload({
      watchId: 't',
      target: 'example.com',
      newFindings: 0,
      resolvedFindings: 0,
      totalFindings: 0,
      critical: 0,
      high: 0,
    })
    const after = new Date().toISOString()

    expect(payload.timestamp >= before).toBe(true)
    expect(payload.timestamp <= after).toBe(true)
  })
})
