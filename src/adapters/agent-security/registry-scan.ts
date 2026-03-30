/**
 * MCP server registry scanner.
 * Pure TypeScript -- no external dependencies.
 * Batch scans MCP config for malicious tool descriptions and suspicious server entries.
 */

import { readFileSync, existsSync } from 'node:fs'
import { cli, Strategy } from '../../registry.js'
import { auditContent } from './mcp-audit.js'
import type { ExecContext } from '../../types.js'

// --- Types ---

type RiskLevel = 'HIGH' | 'MEDIUM' | 'LOW' | 'NONE'

interface McpServerEntry {
  command?: string
  args?: string[]
  env?: Record<string, string>
  [key: string]: unknown
}

interface McpConfig {
  mcpServers?: Record<string, McpServerEntry>
  [key: string]: unknown
}

interface RegistryScanRow {
  server_name: string
  tool_count: number
  findings: number
  risk_level: RiskLevel
  [key: string]: unknown
}

interface ServerFinding {
  type: string
  detail: string
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'
}

// --- Suspicious Pattern Detection ---

const SUSPICIOUS_URL_PATTERN = /https?:\/\/(?!(?:registry\.npmjs\.org|github\.com|gitlab\.com|npmjs\.com|unpkg\.com|cdn\.jsdelivr\.net))[^\s'"]+/i

const DANGEROUS_FLAGS = [
  '--allow-scripts',
  '--unsafe-perm',
  '--ignore-scripts=false',
  '--trust-all',
  '--no-verify',
  '--disable-security',
  '--allow-root',
]

const KNOWN_SAFE_PACKAGES = new Set([
  '@modelcontextprotocol/server-filesystem',
  '@modelcontextprotocol/server-brave-search',
  '@modelcontextprotocol/server-github',
  '@modelcontextprotocol/server-gitlab',
  '@modelcontextprotocol/server-google-maps',
  '@modelcontextprotocol/server-memory',
  '@modelcontextprotocol/server-postgres',
  '@modelcontextprotocol/server-puppeteer',
  '@modelcontextprotocol/server-slack',
  '@modelcontextprotocol/server-sequential-thinking',
  '@modelcontextprotocol/server-everything',
  'mcp-server-fetch',
])

function checkServerArgs(args: readonly string[]): readonly ServerFinding[] {
  const findings: ServerFinding[] = []

  for (const arg of args) {
    // Check for suspicious URLs
    if (SUSPICIOUS_URL_PATTERN.test(arg)) {
      findings.push({
        type: 'SUSPICIOUS_URL',
        detail: `Argument contains URL from unknown domain: ${arg}`,
        severity: 'HIGH',
      })
    }

    // Check for dangerous flags
    for (const flag of DANGEROUS_FLAGS) {
      if (arg.includes(flag)) {
        findings.push({
          type: 'DANGEROUS_FLAG',
          detail: `Dangerous flag detected: ${flag}`,
          severity: 'HIGH',
        })
      }
    }

    // Check for unknown scoped packages (can't verify downloads offline)
    if (arg.startsWith('@') && arg.includes('/') && !KNOWN_SAFE_PACKAGES.has(arg)) {
      findings.push({
        type: 'UNKNOWN_PACKAGE',
        detail: `Unknown scoped package — verify manually: ${arg}`,
        severity: 'MEDIUM',
      })
    }
  }

  return findings
}

function checkServerCommand(command: string): readonly ServerFinding[] {
  const findings: ServerFinding[] = []

  // Flag if using raw shell commands
  const shellCommands = ['bash', 'sh', 'cmd', 'powershell', 'pwsh']
  if (shellCommands.includes(command)) {
    findings.push({
      type: 'SHELL_COMMAND',
      detail: `Server uses raw shell command: ${command}`,
      severity: 'HIGH',
    })
  }

  return findings
}

function computeRiskLevel(findings: readonly ServerFinding[]): RiskLevel {
  if (findings.length === 0) return 'NONE'
  if (findings.some((f) => f.severity === 'CRITICAL')) return 'HIGH'
  if (findings.some((f) => f.severity === 'HIGH')) return 'HIGH'
  if (findings.some((f) => f.severity === 'MEDIUM')) return 'MEDIUM'
  return 'LOW'
}

// --- Main Scan Logic ---

export function scanMcpRegistry(configContent: string): readonly RegistryScanRow[] {
  let config: McpConfig
  try {
    config = JSON.parse(configContent) as McpConfig
  } catch {
    throw new Error('Invalid JSON in MCP config file')
  }

  const servers = config.mcpServers
  if (!servers || typeof servers !== 'object') {
    throw new Error('MCP config missing "mcpServers" object')
  }

  const rows: RegistryScanRow[] = []

  for (const [serverName, entry] of Object.entries(servers)) {
    const allFindings: ServerFinding[] = []

    // Check server command
    if (entry.command) {
      allFindings.push(...checkServerCommand(entry.command))
    }

    // Check server args
    if (Array.isArray(entry.args)) {
      allFindings.push(...checkServerArgs(entry.args))
    }

    // Run mcp-audit content checks on stringified entry for description patterns
    const entryString = JSON.stringify(entry, null, 2)
    const auditFindings = auditContent(entryString, serverName)
    for (const af of auditFindings) {
      allFindings.push({
        type: af.rule_id,
        detail: af.finding,
        severity: af.severity,
      })
    }

    // Count tool definitions if present
    const toolCount = Array.isArray((entry as Record<string, unknown>).tools)
      ? ((entry as Record<string, unknown>).tools as unknown[]).length
      : 0

    const riskLevel = computeRiskLevel(allFindings)

    rows.push({
      server_name: serverName,
      tool_count: toolCount,
      findings: allFindings.length,
      risk_level: riskLevel,
    })
  }

  return rows
}

// --- CLI Registration ---

cli({
  provider: 'agent-security',
  name: 'registry-scan',
  description:
    'Batch scan MCP server registry for known-malicious tool descriptions',
  strategy: Strategy.FREE,
  domain: 'agent-security',
  args: {
    registry: {
      type: 'string',
      required: true,
      help: 'Path to MCP config JSON (claude_desktop_config.json or similar)',
    },
  },
  columns: ['server_name', 'tool_count', 'findings', 'risk_level'],
  timeout: 60,

  async func(ctx: ExecContext, args: Record<string, unknown>) {
    const registryPath = args.registry as string

    if (!existsSync(registryPath)) {
      throw new Error(`MCP config not found: ${registryPath}`)
    }

    const content = readFileSync(registryPath, 'utf-8')
    ctx.log.info(`Scanning MCP registry: ${registryPath}`)

    const rows = scanMcpRegistry(content)

    const highRisk = rows.filter((r) => r.risk_level === 'HIGH').length
    ctx.log.info(
      `Registry scan complete: ${rows.length} servers, ${highRisk} high-risk`,
    )

    return [...rows]
  },
})
