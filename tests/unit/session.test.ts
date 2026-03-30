import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { mkdtempSync, rmSync, existsSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import {
  createSession,
  loadSession,
  saveSession,
  listSessions,
  sessionExists,
  getActiveSessionName,
  setActiveSessionName,
  clearActiveSession,
  setBaseDir,
} from '../../src/session/store.js'
import { getActiveSession, recordStep } from '../../src/session/recorder.js'
import type { Session } from '../../src/session/types.js'

describe('Engagement Session Manager', () => {
  let tmpDir: string

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), 'opensec-session-test-'))
    setBaseDir(tmpDir)
  })

  afterEach(() => {
    setBaseDir(null)
    rmSync(tmpDir, { recursive: true, force: true })
  })

  // -----------------------------------------------------------------------
  // Session creation
  // -----------------------------------------------------------------------

  it('creates a session file with correct initial state', () => {
    const session = createSession('q2-pentest', 'example.com')

    expect(session.name).toBe('q2-pentest')
    expect(session.target).toBe('example.com')
    expect(session.status).toBe('active')
    expect(session.steps).toEqual([])
    expect(session.summary).toEqual({
      commands_run: 0,
      total_findings: 0,
      by_severity: {},
      duration_ms: 0,
    })
    expect(session.createdAt).toBeTruthy()
    expect(session.updatedAt).toBeTruthy()

    // Verify file was actually written
    const filePath = join(tmpDir, 'sessions', 'q2-pentest.json')
    expect(existsSync(filePath)).toBe(true)

    const raw = JSON.parse(readFileSync(filePath, 'utf-8'))
    expect(raw.name).toBe('q2-pentest')
  })

  // -----------------------------------------------------------------------
  // Session load and existence check
  // -----------------------------------------------------------------------

  it('loads an existing session and returns null for missing ones', () => {
    createSession('test-session', '10.0.0.1')

    const loaded = loadSession('test-session')
    expect(loaded).not.toBeNull()
    expect(loaded!.name).toBe('test-session')
    expect(loaded!.target).toBe('10.0.0.1')

    const missing = loadSession('nonexistent')
    expect(missing).toBeNull()
  })

  it('reports session existence correctly', () => {
    expect(sessionExists('new-session')).toBe(false)
    createSession('new-session', 'target.io')
    expect(sessionExists('new-session')).toBe(true)
  })

  // -----------------------------------------------------------------------
  // Active session tracking
  // -----------------------------------------------------------------------

  it('tracks the active session via active-session file', () => {
    expect(getActiveSessionName()).toBeNull()
    expect(getActiveSession()).toBeNull()

    setActiveSessionName('my-session')
    expect(getActiveSessionName()).toBe('my-session')
    expect(getActiveSession()).toBe('my-session')

    clearActiveSession()
    expect(getActiveSessionName()).toBeNull()
  })

  // -----------------------------------------------------------------------
  // Step recording
  // -----------------------------------------------------------------------

  it('records steps and updates session summary', () => {
    createSession('record-test', 'example.com')
    setActiveSessionName('record-test')

    recordStep('nuclei/scan', { target: 'example.com' }, 5, 1200)
    recordStep('subfinder/enum', { domain: 'example.com' }, 12, 3400)

    const session = loadSession('record-test')
    expect(session).not.toBeNull()
    expect(session!.steps).toHaveLength(2)

    expect(session!.steps[0].command).toBe('nuclei/scan')
    expect(session!.steps[0].findings_count).toBe(5)
    expect(session!.steps[0].duration_ms).toBe(1200)
    expect(session!.steps[0].args).toEqual({ target: 'example.com' })
    expect(session!.steps[0].timestamp).toBeTruthy()

    expect(session!.steps[1].command).toBe('subfinder/enum')
    expect(session!.steps[1].findings_count).toBe(12)

    expect(session!.summary.commands_run).toBe(2)
    expect(session!.summary.total_findings).toBe(17)
    expect(session!.summary.duration_ms).toBe(4600)
  })

  it('does not record steps when no session is active', () => {
    createSession('idle-session', 'example.com')
    // Intentionally NOT setting active session

    recordStep('nuclei/scan', { target: 'example.com' }, 3, 500)

    const session = loadSession('idle-session')
    expect(session!.steps).toHaveLength(0)
    expect(session!.summary.commands_run).toBe(0)
  })

  // -----------------------------------------------------------------------
  // Session list
  // -----------------------------------------------------------------------

  it('lists all sessions sorted by updatedAt descending', () => {
    const s1 = createSession('alpha', 'a.com')
    const s2 = createSession('beta', 'b.com')

    // Force beta to have a later updatedAt
    const updatedBeta: Session = {
      ...s2,
      updatedAt: new Date(Date.now() + 1000).toISOString(),
    }
    saveSession(updatedBeta)

    const sessions = listSessions()
    expect(sessions).toHaveLength(2)
    expect(sessions[0].name).toBe('beta')
    expect(sessions[1].name).toBe('alpha')
  })

  // -----------------------------------------------------------------------
  // Session stop (mark completed)
  // -----------------------------------------------------------------------

  it('marks a session as completed when saved with status change', () => {
    const session = createSession('complete-me', 'target.io')
    expect(session.status).toBe('active')

    const completed: Session = {
      ...session,
      status: 'completed',
      updatedAt: new Date().toISOString(),
    }
    saveSession(completed)

    const reloaded = loadSession('complete-me')
    expect(reloaded!.status).toBe('completed')
  })

  // -----------------------------------------------------------------------
  // Recording does not mutate completed sessions
  // -----------------------------------------------------------------------

  it('does not record steps to a completed session', () => {
    createSession('done-session', 'example.com')
    setActiveSessionName('done-session')

    const session = loadSession('done-session')!
    const completed: Session = {
      ...session,
      status: 'completed',
    }
    saveSession(completed)

    recordStep('nuclei/scan', { target: 'example.com' }, 5, 1000)

    const reloaded = loadSession('done-session')
    expect(reloaded!.steps).toHaveLength(0)
    expect(reloaded!.summary.commands_run).toBe(0)
  })
})
