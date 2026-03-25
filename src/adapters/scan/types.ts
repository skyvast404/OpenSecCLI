export type EntryPointKind =
  | 'http_route'
  | 'rpc_handler'
  | 'websocket'
  | 'cli_command'
  | 'job_handler'
  | 'file_entry'

export interface EntryPoint {
  file: string
  line: number
  kind: EntryPointKind
  method?: string
  pattern?: string
  framework?: string
  [key: string]: unknown
}

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'

export interface RawFinding {
  rule_id: string
  severity: Severity
  message: string
  file_path: string
  start_line: number
  cwe: string
  tools_used: string[]
  evidence_paths?: EvidencePath[]
  metadata?: Record<string, unknown>
}

export interface EvidencePath {
  source?: { file: string; line: number; label?: string }
  sink?: { file: string; line: number; label?: string }
  through?: Array<{ file: string; line: number; label?: string }>
}

export interface GitSignal {
  commit: string
  message: string
  files: string[]
  diff_summary?: string
  keywords?: string[]
}

export interface PhaseMetric {
  adapter: string
  latency_ms: number
  findings_count: number
  status: 'completed' | 'skipped' | 'failed' | 'timed_out'
  error?: string
}

export interface ProjectMap {
  path: string
  languages: string[]
  frameworks: string[]
  entry_points: EntryPoint[]
  git_security_signals: GitSignal[]
  source_files: string[]
  architecture_summary?: string
}

export interface ScanReport {
  target: string
  duration_ms: number
  summary: {
    total: number
    critical: number
    high: number
    medium: number
    low: number
  }
  findings: RawFinding[]
  phase_metrics: PhaseMetric[]
  tools_used: string[]
}
