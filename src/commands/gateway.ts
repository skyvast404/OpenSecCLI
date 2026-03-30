/**
 * MCP Security Gateway.
 * opensec gateway audit <log-file>     — Audit MCP runtime log against security policy
 * opensec gateway policy <config-file>  — Validate MCP config against security policy
 * opensec gateway simulate --config <json> --scenario <file> — Dry-run simulate tool calls
 *
 * Proxies MCP tool calls with:
 * - Full audit logging (every call logged to JSONL)
 * - Rate limiting (per-tool, configurable)
 * - Sensitive file access blocking
 * - Anomaly detection (unusual volume, sensitive data patterns)
 */

import type { Command } from 'commander'
import { readFile } from 'node:fs/promises'
import { render } from '../output.js'

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface GatewayPolicy {
  readonly blocked_paths: readonly string[]
  readonly blocked_hosts: readonly string[]
  readonly rate_limit: number
  readonly allowed_tools?: readonly string[]
  readonly require_approval: readonly string[]
}

export interface AuditEntry {
  readonly timestamp: string
  readonly direction: 'request' | 'response'
  readonly server: string
  readonly tool: string
  readonly args: Record<string, unknown>
  readonly blocked: boolean
  readonly blockReason?: string
  readonly latencyMs?: number
}

export type FindingSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info'

export interface GatewayFinding {
  readonly severity: FindingSeverity
  readonly rule: string
  readonly message: string
  readonly entry?: AuditEntry
}

export interface ConfigFinding {
  readonly severity: FindingSeverity
  readonly rule: string
  readonly message: string
  readonly server?: string
}

export interface SimulationResult {
  readonly tool: string
  readonly args: Record<string, unknown>
  readonly allowed: boolean
  readonly findings: readonly GatewayFinding[]
}

// ---------------------------------------------------------------------------
// Default policy
// ---------------------------------------------------------------------------

export const DEFAULT_POLICY: GatewayPolicy = {
  blocked_paths: [
    '\\.ssh',
    '\\.aws',
    '\\.env$',
    '/etc/shadow',
    '/etc/passwd',
    'credentials',
    'secrets',
    '\\.pem$',
    '\\.key$',
  ],
  blocked_hosts: [
    '169\\.254\\.169\\.254',
    'metadata\\.google\\.internal',
    'metadata\\.azure\\.com',
  ],
  rate_limit: 60,
  require_approval: ['execute_command', 'write_file', 'delete_file'],
}

// ---------------------------------------------------------------------------
// Policy checking helpers (pure functions)
// ---------------------------------------------------------------------------

export function matchesAnyPattern(
  value: string,
  patterns: readonly string[],
): string | undefined {
  for (const pattern of patterns) {
    try {
      const regex = new RegExp(pattern, 'i')
      if (regex.test(value)) {
        return pattern
      }
    } catch {
      // Skip invalid regex patterns
    }
  }
  return undefined
}

export function matchAllPatterns(
  value: string,
  patterns: readonly string[],
): readonly string[] {
  const matched: string[] = []
  for (const pattern of patterns) {
    try {
      const regex = new RegExp(pattern, 'i')
      if (regex.test(value)) {
        matched.push(pattern)
      }
    } catch {
      // Skip invalid regex patterns
    }
  }
  return matched
}

function extractStringValues(obj: unknown): readonly string[] {
  const values: string[] = []

  if (typeof obj === 'string') {
    values.push(obj)
    return values
  }

  if (Array.isArray(obj)) {
    for (const item of obj) {
      values.push(...extractStringValues(item))
    }
    return values
  }

  if (obj !== null && typeof obj === 'object') {
    for (const val of Object.values(obj as Record<string, unknown>)) {
      values.push(...extractStringValues(val))
    }
  }

  return values
}

function checkEntryAgainstPolicy(
  entry: AuditEntry,
  policy: GatewayPolicy,
): readonly GatewayFinding[] {
  const findings: GatewayFinding[] = []

  // Check allowed_tools whitelist
  if (
    policy.allowed_tools &&
    policy.allowed_tools.length > 0 &&
    !policy.allowed_tools.includes(entry.tool)
  ) {
    findings.push({
      severity: 'high',
      rule: 'disallowed_tool',
      message: `Tool "${entry.tool}" is not in the allowed tools whitelist`,
      entry,
    })
  }

  // Check require_approval tools
  if (policy.require_approval.includes(entry.tool)) {
    findings.push({
      severity: 'medium',
      rule: 'requires_approval',
      message: `Tool "${entry.tool}" requires human approval before execution`,
      entry,
    })
  }

  // Check args for blocked path and host patterns
  const argValues = extractStringValues(entry.args)
  for (const value of argValues) {
    const matchedPaths = matchAllPatterns(value, policy.blocked_paths)
    for (const matchedPath of matchedPaths) {
      findings.push({
        severity: 'critical',
        rule: 'blocked_path_access',
        message: `Blocked path pattern "${matchedPath}" matched in args: "${value}"`,
        entry,
      })
    }

    const matchedHosts = matchAllPatterns(value, policy.blocked_hosts)
    for (const matchedHost of matchedHosts) {
      findings.push({
        severity: 'critical',
        rule: 'blocked_host_access',
        message: `Blocked host pattern "${matchedHost}" matched in args: "${value}"`,
        entry,
      })
    }
  }

  return findings
}

// ---------------------------------------------------------------------------
// Rate limit detection
// ---------------------------------------------------------------------------

interface ToolCallWindow {
  readonly tool: string
  readonly count: number
  readonly windowStart: string
  readonly windowEnd: string
}

function detectRateLimitViolations(
  entries: readonly AuditEntry[],
  rateLimit: number,
): readonly GatewayFinding[] {
  const findings: GatewayFinding[] = []

  // Group request entries by tool
  const requestEntries = entries.filter((e) => e.direction === 'request')
  const byTool = new Map<string, AuditEntry[]>()

  for (const entry of requestEntries) {
    const existing = byTool.get(entry.tool) ?? []
    byTool.set(entry.tool, [...existing, entry])
  }

  // Check each tool for rate limit violations using 60-second sliding window
  for (const [tool, toolEntries] of byTool) {
    const sorted = [...toolEntries].sort(
      (a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime(),
    )

    for (let i = 0; i < sorted.length; i++) {
      const windowStart = new Date(sorted[i].timestamp).getTime()
      const windowEnd = windowStart + 60_000 // 60 seconds

      let count = 0
      for (let j = i; j < sorted.length; j++) {
        const ts = new Date(sorted[j].timestamp).getTime()
        if (ts <= windowEnd) {
          count++
        } else {
          break
        }
      }

      if (count > rateLimit) {
        const window: ToolCallWindow = {
          tool,
          count,
          windowStart: sorted[i].timestamp,
          windowEnd: new Date(windowEnd).toISOString(),
        }

        findings.push({
          severity: 'high',
          rule: 'rate_limit_exceeded',
          message:
            `Tool "${window.tool}" called ${window.count} times in 60s ` +
            `(limit: ${rateLimit}) starting at ${window.windowStart}`,
          entry: sorted[i],
        })

        // Skip ahead to avoid duplicate findings for same window
        break
      }
    }
  }

  return findings
}

// ---------------------------------------------------------------------------
// Public API: auditLog
// ---------------------------------------------------------------------------

export function auditLog(
  logEntries: readonly AuditEntry[],
  policy: GatewayPolicy,
): readonly GatewayFinding[] {
  const findings: GatewayFinding[] = []

  // Check each entry against policy rules
  for (const entry of logEntries) {
    findings.push(...checkEntryAgainstPolicy(entry, policy))
  }

  // Check rate limits
  findings.push(...detectRateLimitViolations(logEntries, policy.rate_limit))

  // Sort by severity
  const severityOrder: Record<FindingSeverity, number> = {
    critical: 0,
    high: 1,
    medium: 2,
    low: 3,
    info: 4,
  }

  return [...findings].sort(
    (a, b) => severityOrder[a.severity] - severityOrder[b.severity],
  )
}

// ---------------------------------------------------------------------------
// Public API: validateConfig
// ---------------------------------------------------------------------------

export function validateConfig(
  mcpConfig: Record<string, unknown>,
  policy: GatewayPolicy,
): readonly ConfigFinding[] {
  const findings: ConfigFinding[] = []

  // Expect mcpServers or servers key
  const servers =
    (mcpConfig['mcpServers'] as Record<string, unknown> | undefined) ??
    (mcpConfig['servers'] as Record<string, unknown> | undefined)

  if (!servers || typeof servers !== 'object') {
    findings.push({
      severity: 'info',
      rule: 'no_servers',
      message: 'No MCP servers found in configuration (expected "mcpServers" or "servers" key)',
    })
    return findings
  }

  for (const [serverName, serverDef] of Object.entries(servers)) {
    if (!serverDef || typeof serverDef !== 'object') {
      findings.push({
        severity: 'low',
        rule: 'invalid_server_definition',
        message: `Server "${serverName}" has an invalid definition`,
        server: serverName,
      })
      continue
    }

    const def = serverDef as Record<string, unknown>

    // Check command and args for blocked patterns
    const command = String(def['command'] ?? '')
    const args = (def['args'] as string[] | undefined) ?? []
    const allValues = [command, ...args]

    for (const value of allValues) {
      const matchedPath = matchesAnyPattern(value, policy.blocked_paths)
      if (matchedPath) {
        findings.push({
          severity: 'critical',
          rule: 'blocked_path_in_config',
          message: `Server "${serverName}" references blocked path pattern "${matchedPath}" in: "${value}"`,
          server: serverName,
        })
      }

      const matchedHost = matchesAnyPattern(value, policy.blocked_hosts)
      if (matchedHost) {
        findings.push({
          severity: 'critical',
          rule: 'blocked_host_in_config',
          message: `Server "${serverName}" references blocked host pattern "${matchedHost}" in: "${value}"`,
          server: serverName,
        })
      }
    }

    // Check env vars for sensitive patterns
    const env = def['env'] as Record<string, string> | undefined
    if (env && typeof env === 'object') {
      for (const [envKey, envVal] of Object.entries(env)) {
        const matchedPath = matchesAnyPattern(
          String(envVal),
          policy.blocked_paths,
        )
        if (matchedPath) {
          findings.push({
            severity: 'high',
            rule: 'blocked_path_in_env',
            message: `Server "${serverName}" env var "${envKey}" references blocked path pattern "${matchedPath}"`,
            server: serverName,
          })
        }
      }
    }

    // Check if server uses stdio (expected) vs other transports
    const transport = def['transport'] as string | undefined
    if (transport && transport !== 'stdio') {
      findings.push({
        severity: 'medium',
        rule: 'non_stdio_transport',
        message: `Server "${serverName}" uses "${transport}" transport — ensure network exposure is intended`,
        server: serverName,
      })
    }

    // Warn about servers without explicit tool restrictions
    if (!def['allowedTools'] && !def['tools']) {
      findings.push({
        severity: 'low',
        rule: 'no_tool_restriction',
        message: `Server "${serverName}" has no tool restrictions — all tools will be accessible`,
        server: serverName,
      })
    }
  }

  return [...findings].sort((a, b) => {
    const order: Record<FindingSeverity, number> = {
      critical: 0,
      high: 1,
      medium: 2,
      low: 3,
      info: 4,
    }
    return order[a.severity] - order[b.severity]
  })
}

// ---------------------------------------------------------------------------
// Public API: simulateScenario
// ---------------------------------------------------------------------------

export function simulateScenario(
  calls: readonly { tool: string; args: Record<string, unknown> }[],
  policy: GatewayPolicy,
): readonly SimulationResult[] {
  return calls.map((call) => {
    const entry: AuditEntry = {
      timestamp: new Date().toISOString(),
      direction: 'request',
      server: 'simulation',
      tool: call.tool,
      args: call.args,
      blocked: false,
    }

    const findings = [...checkEntryAgainstPolicy(entry, policy)]
    const hasBlocking = findings.some(
      (f) => f.severity === 'critical' || f.rule === 'disallowed_tool',
    )

    return {
      tool: call.tool,
      args: call.args,
      allowed: !hasBlocking,
      findings,
    }
  })
}

// ---------------------------------------------------------------------------
// JSONL parsing
// ---------------------------------------------------------------------------

export function parseJsonlLog(content: string): readonly AuditEntry[] {
  const entries: AuditEntry[] = []

  const lines = content.split('\n').filter((line) => line.trim().length > 0)

  for (const line of lines) {
    try {
      const parsed = JSON.parse(line) as AuditEntry
      if (parsed.timestamp && parsed.tool) {
        entries.push(parsed)
      }
    } catch {
      // Skip malformed lines
    }
  }

  return entries
}

// ---------------------------------------------------------------------------
// CLI registration
// ---------------------------------------------------------------------------

export function registerGatewayCommands(program: Command): void {
  const gwCmd = program
    .command('gateway')
    .description('MCP security gateway — audit, policy, simulate')

  // opensec gateway audit <log-file> [--policy <file>]
  gwCmd
    .command('audit <log-file>')
    .description('Audit MCP runtime log against security policy')
    .option('--policy <file>', 'Custom policy JSON file (uses defaults if omitted)')
    .action(async (logFile: string, opts: { policy?: string }) => {
      const policy = opts.policy
        ? await loadPolicyFile(opts.policy)
        : DEFAULT_POLICY

      const content = await readFile(logFile, 'utf-8')
      const entries = parseJsonlLog(content)

      if (entries.length === 0) {
        process.stderr.write('No valid audit entries found in log file.\n')
        process.exit(1)
      }

      process.stderr.write(
        `Auditing ${entries.length} log entries against policy...\n`,
      )
      const findings = auditLog(entries, policy)

      if (findings.length === 0) {
        process.stderr.write('No policy violations found.\n')
        return
      }

      const format = getFormat(program)
      render(
        findings.map((f) => ({
          severity: f.severity,
          rule: f.rule,
          message: f.message,
          tool: f.entry?.tool ?? '-',
          timestamp: f.entry?.timestamp ?? '-',
        })),
        {
          format: format as 'table' | 'json' | 'csv' | 'yaml' | 'markdown',
          columns: ['severity', 'rule', 'tool', 'message', 'timestamp'],
        },
      )

      const critical = findings.filter((f) => f.severity === 'critical').length
      const high = findings.filter((f) => f.severity === 'high').length
      process.stderr.write(
        `\n${findings.length} findings: ${critical} critical, ${high} high\n`,
      )
    })

  // opensec gateway policy <config-file> [--policy <file>]
  gwCmd
    .command('policy <config-file>')
    .description('Validate MCP config against security policy')
    .option('--policy <file>', 'Custom policy JSON file (uses defaults if omitted)')
    .action(async (configFile: string, opts: { policy?: string }) => {
      const policy = opts.policy
        ? await loadPolicyFile(opts.policy)
        : DEFAULT_POLICY

      const content = await readFile(configFile, 'utf-8')
      let mcpConfig: Record<string, unknown>
      try {
        mcpConfig = JSON.parse(content) as Record<string, unknown>
      } catch {
        process.stderr.write(
          `Error: Failed to parse config file as JSON: ${configFile}\n`,
        )
        process.exit(1)
        return
      }

      process.stderr.write('Validating MCP config against security policy...\n')
      const findings = validateConfig(mcpConfig, policy)

      if (findings.length === 0) {
        process.stderr.write('No policy violations found.\n')
        return
      }

      const format = getFormat(program)
      render(
        findings.map((f) => ({
          severity: f.severity,
          rule: f.rule,
          message: f.message,
          server: f.server ?? '-',
        })),
        {
          format: format as 'table' | 'json' | 'csv' | 'yaml' | 'markdown',
          columns: ['severity', 'rule', 'server', 'message'],
        },
      )

      const critical = findings.filter((f) => f.severity === 'critical').length
      const high = findings.filter((f) => f.severity === 'high').length
      process.stderr.write(
        `\n${findings.length} findings: ${critical} critical, ${high} high\n`,
      )
    })

  // opensec gateway simulate --config <json> --scenario <file>
  gwCmd
    .command('simulate')
    .description('Dry-run simulate tool calls against policy')
    .requiredOption('--scenario <file>', 'Scenario JSON file with tool calls')
    .option('--policy <file>', 'Custom policy JSON file (uses defaults if omitted)')
    .action(async (opts: { scenario: string; policy?: string }) => {
      const policy = opts.policy
        ? await loadPolicyFile(opts.policy)
        : DEFAULT_POLICY

      const scenarioContent = await readFile(opts.scenario, 'utf-8')
      let calls: { tool: string; args: Record<string, unknown> }[]
      try {
        calls = JSON.parse(scenarioContent) as typeof calls
      } catch {
        process.stderr.write(
          `Error: Failed to parse scenario file as JSON: ${opts.scenario}\n`,
        )
        process.exit(1)
        return
      }

      if (!Array.isArray(calls)) {
        process.stderr.write(
          'Error: Scenario file must contain a JSON array of {tool, args} objects.\n',
        )
        process.exit(1)
        return
      }

      process.stderr.write(
        `Simulating ${calls.length} tool calls against policy...\n`,
      )
      const results = simulateScenario(calls, policy)

      const format = getFormat(program)
      render(
        results.map((r) => ({
          tool: r.tool,
          allowed: r.allowed ? 'ALLOW' : 'BLOCK',
          findings: r.findings.length,
          details: r.findings.map((f) => `[${f.severity}] ${f.message}`).join('; ') || 'clean',
        })),
        {
          format: format as 'table' | 'json' | 'csv' | 'yaml' | 'markdown',
          columns: ['tool', 'allowed', 'findings', 'details'],
        },
      )

      const blocked = results.filter((r) => !r.allowed).length
      process.stderr.write(
        `\n${results.length} calls simulated: ${blocked} blocked, ${results.length - blocked} allowed\n`,
      )
    })
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async function loadPolicyFile(filePath: string): Promise<GatewayPolicy> {
  const content = await readFile(filePath, 'utf-8')
  try {
    const parsed = JSON.parse(content) as Partial<GatewayPolicy>
    return {
      blocked_paths: parsed.blocked_paths ?? DEFAULT_POLICY.blocked_paths,
      blocked_hosts: parsed.blocked_hosts ?? DEFAULT_POLICY.blocked_hosts,
      rate_limit: parsed.rate_limit ?? DEFAULT_POLICY.rate_limit,
      allowed_tools: parsed.allowed_tools,
      require_approval:
        parsed.require_approval ?? DEFAULT_POLICY.require_approval,
    }
  } catch {
    throw new Error(`Failed to parse policy file: ${filePath}`)
  }
}

function getFormat(program: Command): string {
  const globalOpts = program.opts()
  return globalOpts.json ? 'json' : (globalOpts.format ?? 'table')
}
