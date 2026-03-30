/**
 * MCP server runtime log anomaly detector.
 * Pure TypeScript -- no external dependencies.
 * Analyzes JSONL logs for file access, network exfiltration, privilege escalation, and volume anomalies.
 */

import { readFileSync, existsSync } from 'node:fs'
import { cli, Strategy } from '../../registry.js'
import type { ExecContext } from '../../types.js'

// --- Types ---

type AnomalyType =
  | 'FILE_ACCESS'
  | 'NETWORK_EXFIL'
  | 'PRIVILEGE_ESCALATION'
  | 'UNUSUAL_VOLUME'
  | 'CROSS_SERVER_DATA'

type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'

interface LogEntry {
  timestamp?: string
  server?: string
  tool?: string
  args?: Record<string, unknown>
  result?: string
  [key: string]: unknown
}

interface AnomalyRow {
  timestamp: string
  server: string
  tool: string
  anomaly_type: AnomalyType
  severity: Severity
  detail: string
  [key: string]: unknown
}

// --- Sensitive Path Patterns ---

const SENSITIVE_PATHS = [
  '~/.ssh',
  '~/.aws',
  '~/.env',
  '/etc/passwd',
  '/etc/shadow',
  '/etc/sudoers',
  '.env',
  'id_rsa',
  'id_ed25519',
  'credentials',
  'aws/credentials',
  '.gnupg',
  '.kube/config',
  'known_hosts',
  'authorized_keys',
]

const EXFIL_INDICATORS = [
  'token',
  'secret',
  'password',
  'api_key',
  'apikey',
  'access_key',
  'private_key',
  'credential',
  'ssh',
  'BEGIN PRIVATE KEY',
  'BEGIN RSA PRIVATE',
]

const PRIVILEGE_PATTERNS = [
  /\bsudo\b/,
  /\bsu\s+-?\s/,
  /\bas\s+root\b/i,
  /\badmin\b.*\bexec/i,
  /--privileged/,
  /chmod\s+[0-7]*[67][0-7]{2}/,
  /chown\s+root/,
]

// --- Anomaly Detection ---

function checkFileAccess(entry: LogEntry): AnomalyRow | null {
  const argsStr = JSON.stringify(entry.args ?? {}).toLowerCase()
  const resultStr = (entry.result ?? '').toLowerCase()
  const combined = `${argsStr} ${resultStr}`

  for (const sensitivePath of SENSITIVE_PATHS) {
    if (combined.includes(sensitivePath.toLowerCase())) {
      return {
        timestamp: entry.timestamp ?? '',
        server: entry.server ?? 'unknown',
        tool: entry.tool ?? 'unknown',
        anomaly_type: 'FILE_ACCESS',
        severity: 'CRITICAL',
        detail: `Accessing sensitive path: ${sensitivePath}`,
      }
    }
  }

  return null
}

function checkNetworkExfil(entry: LogEntry): AnomalyRow | null {
  const argsStr = JSON.stringify(entry.args ?? {})
  const resultStr = entry.result ?? ''
  const combined = `${argsStr} ${resultStr}`

  const hasNetwork = /https?:\/\/|fetch\(|http\.request|curl\s/.test(combined)
  if (!hasNetwork) return null

  for (const indicator of EXFIL_INDICATORS) {
    if (combined.toLowerCase().includes(indicator.toLowerCase())) {
      return {
        timestamp: entry.timestamp ?? '',
        server: entry.server ?? 'unknown',
        tool: entry.tool ?? 'unknown',
        anomaly_type: 'NETWORK_EXFIL',
        severity: 'CRITICAL',
        detail: `Network request with sensitive data indicator: ${indicator}`,
      }
    }
  }

  return null
}

function checkPrivilegeEscalation(entry: LogEntry): AnomalyRow | null {
  const argsStr = JSON.stringify(entry.args ?? {})
  const resultStr = entry.result ?? ''
  const combined = `${argsStr} ${resultStr}`

  for (const pattern of PRIVILEGE_PATTERNS) {
    if (pattern.test(combined)) {
      return {
        timestamp: entry.timestamp ?? '',
        server: entry.server ?? 'unknown',
        tool: entry.tool ?? 'unknown',
        anomaly_type: 'PRIVILEGE_ESCALATION',
        severity: 'HIGH',
        detail: `Privilege escalation pattern: ${pattern.source}`,
      }
    }
  }

  return null
}

function checkUnusualVolume(
  entries: readonly LogEntry[],
): readonly AnomalyRow[] {
  const findings: AnomalyRow[] = []

  // Group entries by server+tool per minute
  const minuteBuckets = new Map<string, LogEntry[]>()

  for (const entry of entries) {
    const ts = entry.timestamp ?? ''
    // Truncate to minute resolution
    const minute = ts.slice(0, 16) // "2026-03-30T10:00"
    const key = `${entry.server ?? 'unknown'}|${entry.tool ?? 'unknown'}|${minute}`

    const bucket = minuteBuckets.get(key)
    if (bucket) {
      bucket.push(entry)
    } else {
      minuteBuckets.set(key, [entry])
    }
  }

  for (const [key, bucket] of minuteBuckets) {
    if (bucket.length > 100) {
      const [server, tool, minute] = key.split('|')
      findings.push({
        timestamp: minute ?? '',
        server: server ?? 'unknown',
        tool: tool ?? 'unknown',
        anomaly_type: 'UNUSUAL_VOLUME',
        severity: 'HIGH',
        detail: `${bucket.length} calls in 1 minute (threshold: 100)`,
      })
    }
  }

  return findings
}

function checkCrossServerData(
  entries: readonly LogEntry[],
): readonly AnomalyRow[] {
  const findings: AnomalyRow[] = []

  // Track data outputs per server
  const serverOutputs = new Map<string, Set<string>>()

  for (const entry of entries) {
    const server = entry.server ?? 'unknown'
    const result = entry.result ?? ''

    if (result.length > 0) {
      const outputs = serverOutputs.get(server)
      if (outputs) {
        outputs.add(result)
      } else {
        serverOutputs.set(server, new Set([result]))
      }
    }
  }

  // Check if any entry's args reference another server's output
  for (const entry of entries) {
    const currentServer = entry.server ?? 'unknown'
    const argsStr = JSON.stringify(entry.args ?? {})

    for (const [otherServer, outputs] of serverOutputs) {
      if (otherServer === currentServer) continue

      for (const output of outputs) {
        // Only flag if a meaningful substring (>20 chars) of another server's output appears in args
        if (output.length > 20 && argsStr.includes(output)) {
          findings.push({
            timestamp: entry.timestamp ?? '',
            server: currentServer,
            tool: entry.tool ?? 'unknown',
            anomaly_type: 'CROSS_SERVER_DATA',
            severity: 'MEDIUM',
            detail: `Args contain data from server "${otherServer}"`,
          })
        }
      }
    }
  }

  return findings
}

// --- Main Detection Pipeline ---

export function detectAnomalies(entry: LogEntry): readonly AnomalyRow[] {
  const anomalies: AnomalyRow[] = []

  const fileAccess = checkFileAccess(entry)
  if (fileAccess) anomalies.push(fileAccess)

  const networkExfil = checkNetworkExfil(entry)
  if (networkExfil) anomalies.push(networkExfil)

  const privEsc = checkPrivilegeEscalation(entry)
  if (privEsc) anomalies.push(privEsc)

  return anomalies
}

export function analyzeRuntimeLog(content: string): readonly AnomalyRow[] {
  const lines = content.trim().split('\n').filter((l) => l.trim().length > 0)
  const entries: LogEntry[] = []
  const perEntryAnomalies: AnomalyRow[] = []

  for (const line of lines) {
    try {
      const entry = JSON.parse(line) as LogEntry
      entries.push(entry)
      perEntryAnomalies.push(...detectAnomalies(entry))
    } catch {
      // Skip malformed lines
    }
  }

  // Batch checks across all entries
  const volumeAnomalies = checkUnusualVolume(entries)
  const crossServerAnomalies = checkCrossServerData(entries)

  const allAnomalies = [
    ...perEntryAnomalies,
    ...volumeAnomalies,
    ...crossServerAnomalies,
  ]

  // Sort by severity
  const severityOrder: Record<Severity, number> = {
    CRITICAL: 0,
    HIGH: 1,
    MEDIUM: 2,
    LOW: 3,
  }

  return [...allAnomalies].sort(
    (a, b) => severityOrder[a.severity] - severityOrder[b.severity],
  )
}

// --- CLI Registration ---

cli({
  provider: 'agent-security',
  name: 'runtime-monitor',
  description:
    'Analyze MCP server runtime logs for anomalous tool usage patterns',
  strategy: Strategy.FREE,
  domain: 'agent-security',
  args: {
    log_file: {
      type: 'string',
      required: true,
      help: 'Path to MCP runtime log (JSONL format)',
    },
  },
  columns: ['timestamp', 'server', 'tool', 'anomaly_type', 'severity', 'detail'],
  timeout: 60,

  async func(ctx: ExecContext, args: Record<string, unknown>) {
    const logFile = args.log_file as string

    if (!existsSync(logFile)) {
      throw new Error(`Log file not found: ${logFile}`)
    }

    const content = readFileSync(logFile, 'utf-8')
    ctx.log.info(`Analyzing runtime log: ${logFile}`)

    const anomalies = analyzeRuntimeLog(content)

    const critical = anomalies.filter((a) => a.severity === 'CRITICAL').length
    ctx.log.info(
      `Runtime analysis complete: ${anomalies.length} anomalies, ${critical} critical`,
    )

    return [...anomalies]
  },
})
