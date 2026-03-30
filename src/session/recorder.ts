/**
 * Session step recorder — auto-records commands when a session is active.
 * Called from execution.ts after each command completes.
 */

import type { Session, SessionStep } from './types.js'
import { getActiveSessionName, loadSession, saveSession } from './store.js'

export function getActiveSession(): string | null {
  return getActiveSessionName()
}

export function recordStep(
  commandId: string,
  args: Record<string, unknown>,
  findingsCount: number,
  durationMs: number,
): void {
  const sessionName = getActiveSessionName()
  if (!sessionName) return

  const session = loadSession(sessionName)
  if (!session || session.status !== 'active') return

  const step: SessionStep = {
    command: commandId,
    args,
    findings_count: findingsCount,
    duration_ms: durationMs,
    timestamp: new Date().toISOString(),
  }

  const updatedSteps = [...session.steps, step]
  const updatedSummary = {
    commands_run: session.summary.commands_run + 1,
    total_findings: session.summary.total_findings + findingsCount,
    by_severity: { ...session.summary.by_severity },
    duration_ms: session.summary.duration_ms + durationMs,
  }

  const updatedSession: Session = {
    ...session,
    steps: updatedSteps,
    summary: updatedSummary,
    updatedAt: new Date().toISOString(),
  }

  saveSession(updatedSession)
}
