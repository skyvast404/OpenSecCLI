/**
 * Data types for the Engagement Session Manager.
 */

export interface SessionStep {
  readonly command: string
  readonly args: Record<string, unknown>
  readonly findings_count: number
  readonly duration_ms: number
  readonly timestamp: string
}

export interface SessionSummary {
  readonly commands_run: number
  readonly total_findings: number
  readonly by_severity: Record<string, number>
  readonly duration_ms: number
}

export interface Session {
  readonly name: string
  readonly target: string
  readonly createdAt: string
  readonly updatedAt: string
  readonly status: 'active' | 'completed'
  readonly steps: readonly SessionStep[]
  readonly summary: SessionSummary
}
