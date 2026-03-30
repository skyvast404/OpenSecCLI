/**
 * Session file I/O — read/write session JSON files.
 * Sessions stored at ~/.openseccli/sessions/<name>.json
 * Active session pointer at ~/.openseccli/active-session
 */

import { readFileSync, writeFileSync, existsSync, mkdirSync, readdirSync, unlinkSync } from 'node:fs'
import { join } from 'node:path'
import { homedir } from 'node:os'
import { CONFIG_DIR_NAME } from '../constants.js'
import type { Session, SessionSummary } from './types.js'

// ---------------------------------------------------------------------------
// Path helpers
// ---------------------------------------------------------------------------

function getSessionsDir(): string {
  return join(homedir(), CONFIG_DIR_NAME, 'sessions')
}

function getActiveSessionPath(): string {
  return join(homedir(), CONFIG_DIR_NAME, 'active-session')
}

function sessionFilePath(name: string): string {
  return join(getSessionsDir(), `${name}.json`)
}

// Allow tests to override the base directory
let baseDirOverride: string | null = null

export function setBaseDir(dir: string | null): void {
  baseDirOverride = dir
}

function resolveSessionsDir(): string {
  if (baseDirOverride) return join(baseDirOverride, 'sessions')
  return getSessionsDir()
}

function resolveActiveSessionPath(): string {
  if (baseDirOverride) return join(baseDirOverride, 'active-session')
  return getActiveSessionPath()
}

function resolveSessionFilePath(name: string): string {
  return join(resolveSessionsDir(), `${name}.json`)
}

// ---------------------------------------------------------------------------
// Ensure directories exist
// ---------------------------------------------------------------------------

function ensureSessionsDir(): void {
  const dir = resolveSessionsDir()
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true })
  }
}

// ---------------------------------------------------------------------------
// Active session
// ---------------------------------------------------------------------------

export function getActiveSessionName(): string | null {
  const path = resolveActiveSessionPath()
  if (!existsSync(path)) return null
  try {
    const content = readFileSync(path, 'utf-8').trim()
    return content || null
  } catch {
    return null
  }
}

export function setActiveSessionName(name: string): void {
  const dir = baseDirOverride ?? join(homedir(), CONFIG_DIR_NAME)
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true })
  }
  writeFileSync(resolveActiveSessionPath(), name, 'utf-8')
}

export function clearActiveSession(): void {
  const path = resolveActiveSessionPath()
  if (existsSync(path)) {
    unlinkSync(path)
  }
}

// ---------------------------------------------------------------------------
// Session CRUD
// ---------------------------------------------------------------------------

export function createSession(name: string, target: string): Session {
  ensureSessionsDir()

  const now = new Date().toISOString()
  const session: Session = {
    name,
    target,
    createdAt: now,
    updatedAt: now,
    status: 'active',
    steps: [],
    summary: {
      commands_run: 0,
      total_findings: 0,
      by_severity: {},
      duration_ms: 0,
    },
  }

  writeFileSync(resolveSessionFilePath(name), JSON.stringify(session, null, 2), 'utf-8')
  return session
}

export function loadSession(name: string): Session | null {
  const path = resolveSessionFilePath(name)
  if (!existsSync(path)) return null
  try {
    const raw = readFileSync(path, 'utf-8')
    return JSON.parse(raw) as Session
  } catch {
    return null
  }
}

export function saveSession(session: Session): void {
  ensureSessionsDir()
  writeFileSync(resolveSessionFilePath(session.name), JSON.stringify(session, null, 2), 'utf-8')
}

export function listSessions(): Session[] {
  const dir = resolveSessionsDir()
  if (!existsSync(dir)) return []

  const files = readdirSync(dir).filter(f => f.endsWith('.json'))
  const sessions: Session[] = []

  for (const file of files) {
    try {
      const raw = readFileSync(join(dir, file), 'utf-8')
      sessions.push(JSON.parse(raw) as Session)
    } catch {
      // skip corrupt files
    }
  }

  return sessions.sort((a, b) => b.updatedAt.localeCompare(a.updatedAt))
}

export function sessionExists(name: string): boolean {
  return existsSync(resolveSessionFilePath(name))
}
