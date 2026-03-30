import { describe, it, expect } from 'vitest'
import {
  auditLog,
  validateConfig,
  simulateScenario,
  parseJsonlLog,
  matchesAnyPattern,
  DEFAULT_POLICY,
} from '../../src/commands/gateway.js'
import type {
  AuditEntry,
  GatewayPolicy,
  GatewayFinding,
  ConfigFinding,
} from '../../src/commands/gateway.js'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeEntry(overrides: Partial<AuditEntry> = {}): AuditEntry {
  return {
    timestamp: '2026-03-30T10:00:00.000Z',
    direction: 'request',
    server: 'test-server',
    tool: 'read_file',
    args: {},
    blocked: false,
    ...overrides,
  }
}

// ---------------------------------------------------------------------------
// matchesAnyPattern
// ---------------------------------------------------------------------------

describe('matchesAnyPattern', () => {
  it('returns matching pattern when value matches', () => {
    const result = matchesAnyPattern('/home/user/.ssh/id_rsa', DEFAULT_POLICY.blocked_paths)
    expect(result).toBe('\\.ssh')
  })

  it('returns undefined when no pattern matches', () => {
    const result = matchesAnyPattern('/home/user/code/app.ts', DEFAULT_POLICY.blocked_paths)
    expect(result).toBeUndefined()
  })

  it('matches cloud metadata endpoints', () => {
    const result = matchesAnyPattern('http://169.254.169.254/latest/meta-data/', DEFAULT_POLICY.blocked_hosts)
    expect(result).toBe('169\\.254\\.169\\.254')
  })

  it('skips invalid regex patterns without throwing', () => {
    const result = matchesAnyPattern('test', ['[invalid'])
    expect(result).toBeUndefined()
  })
})

// ---------------------------------------------------------------------------
// auditLog
// ---------------------------------------------------------------------------

describe('auditLog', () => {
  it('returns empty findings for clean log entries', () => {
    const entries: AuditEntry[] = [
      makeEntry({ tool: 'list_files', args: { path: '/home/user/project' } }),
      makeEntry({ tool: 'read_file', args: { path: '/home/user/project/src/index.ts' } }),
    ]

    const findings = auditLog(entries, DEFAULT_POLICY)
    // Should only have require_approval findings if tools are in that list
    const critical = findings.filter((f) => f.severity === 'critical')
    expect(critical).toHaveLength(0)
  })

  it('detects blocked path access (.ssh)', () => {
    const entries: AuditEntry[] = [
      makeEntry({ tool: 'read_file', args: { path: '/home/user/.ssh/id_rsa' } }),
    ]

    const findings = auditLog(entries, DEFAULT_POLICY)
    const blocked = findings.filter((f) => f.rule === 'blocked_path_access')
    expect(blocked.length).toBeGreaterThanOrEqual(1)
    expect(blocked[0].severity).toBe('critical')
    expect(blocked[0].message).toContain('.ssh')
  })

  it('detects blocked path access (.aws credentials)', () => {
    const entries: AuditEntry[] = [
      makeEntry({ tool: 'read_file', args: { path: '/home/user/.aws/credentials' } }),
    ]

    const findings = auditLog(entries, DEFAULT_POLICY)
    const blocked = findings.filter((f) => f.rule === 'blocked_path_access')
    // Should match both .aws and credentials patterns
    expect(blocked.length).toBeGreaterThanOrEqual(2)
  })

  it('detects blocked host access (cloud metadata)', () => {
    const entries: AuditEntry[] = [
      makeEntry({
        tool: 'http_request',
        args: { url: 'http://169.254.169.254/latest/meta-data/iam/info' },
      }),
    ]

    const findings = auditLog(entries, DEFAULT_POLICY)
    const hostFindings = findings.filter((f) => f.rule === 'blocked_host_access')
    expect(hostFindings.length).toBeGreaterThanOrEqual(1)
    expect(hostFindings[0].severity).toBe('critical')
  })

  it('detects rate limit violations', () => {
    const baseTime = new Date('2026-03-30T10:00:00.000Z').getTime()
    const entries: AuditEntry[] = []

    // Generate 65 calls in 30 seconds (exceeds 60/min limit)
    for (let i = 0; i < 65; i++) {
      entries.push(
        makeEntry({
          timestamp: new Date(baseTime + i * 400).toISOString(),
          tool: 'read_file',
          args: { path: `/project/file${i}.ts` },
        }),
      )
    }

    const findings = auditLog(entries, DEFAULT_POLICY)
    const rateLimited = findings.filter((f) => f.rule === 'rate_limit_exceeded')
    expect(rateLimited.length).toBeGreaterThanOrEqual(1)
    expect(rateLimited[0].severity).toBe('high')
    expect(rateLimited[0].message).toContain('65')
  })

  it('does not flag rate limit when under threshold', () => {
    const baseTime = new Date('2026-03-30T10:00:00.000Z').getTime()
    const entries: AuditEntry[] = []

    // 50 calls over 120 seconds (spread out, under limit)
    for (let i = 0; i < 50; i++) {
      entries.push(
        makeEntry({
          timestamp: new Date(baseTime + i * 2500).toISOString(),
          tool: 'read_file',
          args: { path: `/project/file${i}.ts` },
        }),
      )
    }

    const findings = auditLog(entries, DEFAULT_POLICY)
    const rateLimited = findings.filter((f) => f.rule === 'rate_limit_exceeded')
    expect(rateLimited).toHaveLength(0)
  })

  it('detects disallowed tools when whitelist is set', () => {
    const policy: GatewayPolicy = {
      ...DEFAULT_POLICY,
      allowed_tools: ['read_file', 'list_files'],
    }

    const entries: AuditEntry[] = [
      makeEntry({ tool: 'read_file', args: { path: '/project/ok.ts' } }),
      makeEntry({ tool: 'execute_command', args: { command: 'rm -rf /' } }),
    ]

    const findings = auditLog(entries, policy)
    const disallowed = findings.filter((f) => f.rule === 'disallowed_tool')
    expect(disallowed).toHaveLength(1)
    expect(disallowed[0].message).toContain('execute_command')
  })

  it('detects tools requiring approval', () => {
    const entries: AuditEntry[] = [
      makeEntry({ tool: 'write_file', args: { path: '/project/config.json' } }),
      makeEntry({ tool: 'delete_file', args: { path: '/project/old.ts' } }),
    ]

    const findings = auditLog(entries, DEFAULT_POLICY)
    const approval = findings.filter((f) => f.rule === 'requires_approval')
    expect(approval).toHaveLength(2)
    expect(approval[0].severity).toBe('medium')
  })

  it('sorts findings by severity (critical first)', () => {
    const entries: AuditEntry[] = [
      makeEntry({ tool: 'write_file', args: { path: '/project/ok.ts' } }),
      makeEntry({ tool: 'read_file', args: { path: '/home/user/.ssh/id_rsa' } }),
    ]

    const findings = auditLog(entries, DEFAULT_POLICY)
    expect(findings.length).toBeGreaterThanOrEqual(2)

    // Critical should come before medium
    const firstCriticalIdx = findings.findIndex((f) => f.severity === 'critical')
    const firstMediumIdx = findings.findIndex((f) => f.severity === 'medium')
    if (firstCriticalIdx !== -1 && firstMediumIdx !== -1) {
      expect(firstCriticalIdx).toBeLessThan(firstMediumIdx)
    }
  })

  it('detects .env file access', () => {
    const entries: AuditEntry[] = [
      makeEntry({ tool: 'read_file', args: { path: '/project/.env' } }),
    ]

    const findings = auditLog(entries, DEFAULT_POLICY)
    const blocked = findings.filter((f) => f.rule === 'blocked_path_access')
    expect(blocked.length).toBeGreaterThanOrEqual(1)
  })

  it('detects .pem key file access', () => {
    const entries: AuditEntry[] = [
      makeEntry({ tool: 'read_file', args: { path: '/home/user/server.pem' } }),
    ]

    const findings = auditLog(entries, DEFAULT_POLICY)
    const blocked = findings.filter((f) => f.rule === 'blocked_path_access')
    expect(blocked.length).toBeGreaterThanOrEqual(1)
  })

  it('checks nested args values', () => {
    const entries: AuditEntry[] = [
      makeEntry({
        tool: 'http_request',
        args: {
          config: {
            url: 'http://metadata.google.internal/computeMetadata/v1/',
          },
        },
      }),
    ]

    const findings = auditLog(entries, DEFAULT_POLICY)
    const hostFindings = findings.filter((f) => f.rule === 'blocked_host_access')
    expect(hostFindings.length).toBeGreaterThanOrEqual(1)
  })
})

// ---------------------------------------------------------------------------
// validateConfig
// ---------------------------------------------------------------------------

describe('validateConfig', () => {
  it('returns info finding for config with no servers', () => {
    const findings = validateConfig({}, DEFAULT_POLICY)
    expect(findings).toHaveLength(1)
    expect(findings[0].rule).toBe('no_servers')
    expect(findings[0].severity).toBe('info')
  })

  it('detects blocked paths in server command args', () => {
    const config = {
      mcpServers: {
        'file-reader': {
          command: 'node',
          args: ['server.js', '--root', '/home/user/.ssh'],
        },
      },
    }

    const findings = validateConfig(config, DEFAULT_POLICY)
    const blocked = findings.filter((f) => f.rule === 'blocked_path_in_config')
    expect(blocked.length).toBeGreaterThanOrEqual(1)
    expect(blocked[0].severity).toBe('critical')
    expect(blocked[0].server).toBe('file-reader')
  })

  it('detects blocked hosts in server args', () => {
    const config = {
      mcpServers: {
        proxy: {
          command: 'curl',
          args: ['http://169.254.169.254/latest/meta-data/'],
        },
      },
    }

    const findings = validateConfig(config, DEFAULT_POLICY)
    const blocked = findings.filter((f) => f.rule === 'blocked_host_in_config')
    expect(blocked.length).toBeGreaterThanOrEqual(1)
    expect(blocked[0].severity).toBe('critical')
  })

  it('detects blocked paths in env vars', () => {
    const config = {
      mcpServers: {
        myserver: {
          command: 'node',
          args: ['server.js'],
          env: {
            CONFIG_PATH: '/home/user/.aws/credentials',
          },
        },
      },
    }

    const findings = validateConfig(config, DEFAULT_POLICY)
    const envFindings = findings.filter((f) => f.rule === 'blocked_path_in_env')
    expect(envFindings.length).toBeGreaterThanOrEqual(1)
    expect(envFindings[0].severity).toBe('high')
  })

  it('warns about non-stdio transport', () => {
    const config = {
      mcpServers: {
        remote: {
          command: 'node',
          args: ['server.js'],
          transport: 'sse',
        },
      },
    }

    const findings = validateConfig(config, DEFAULT_POLICY)
    const transportFindings = findings.filter((f) => f.rule === 'non_stdio_transport')
    expect(transportFindings).toHaveLength(1)
    expect(transportFindings[0].severity).toBe('medium')
  })

  it('warns about servers with no tool restrictions', () => {
    const config = {
      mcpServers: {
        unrestricted: {
          command: 'node',
          args: ['server.js'],
        },
      },
    }

    const findings = validateConfig(config, DEFAULT_POLICY)
    const noRestriction = findings.filter((f) => f.rule === 'no_tool_restriction')
    expect(noRestriction).toHaveLength(1)
    expect(noRestriction[0].severity).toBe('low')
  })

  it('accepts clean config with no violations', () => {
    const config = {
      mcpServers: {
        safe: {
          command: 'node',
          args: ['safe-server.js'],
          allowedTools: ['read_file', 'list_files'],
        },
      },
    }

    const findings = validateConfig(config, DEFAULT_POLICY)
    const critical = findings.filter((f) => f.severity === 'critical')
    expect(critical).toHaveLength(0)
  })

  it('handles "servers" key as alternative to "mcpServers"', () => {
    const config = {
      servers: {
        myserver: {
          command: 'node',
          args: ['/home/user/.ssh/steal.js'],
        },
      },
    }

    const findings = validateConfig(config, DEFAULT_POLICY)
    const blocked = findings.filter((f) => f.rule === 'blocked_path_in_config')
    expect(blocked.length).toBeGreaterThanOrEqual(1)
  })

  it('sorts findings by severity', () => {
    const config = {
      mcpServers: {
        bad: {
          command: 'node',
          args: ['/home/user/.ssh/server.js'],
          transport: 'sse',
        },
      },
    }

    const findings = validateConfig(config, DEFAULT_POLICY)
    for (let i = 1; i < findings.length; i++) {
      const order: Record<string, number> = {
        critical: 0,
        high: 1,
        medium: 2,
        low: 3,
        info: 4,
      }
      expect(order[findings[i].severity]).toBeGreaterThanOrEqual(
        order[findings[i - 1].severity],
      )
    }
  })
})

// ---------------------------------------------------------------------------
// simulateScenario
// ---------------------------------------------------------------------------

describe('simulateScenario', () => {
  it('allows clean tool calls', () => {
    const results = simulateScenario(
      [{ tool: 'read_file', args: { path: '/project/src/app.ts' } }],
      DEFAULT_POLICY,
    )

    expect(results).toHaveLength(1)
    expect(results[0].allowed).toBe(true)
  })

  it('blocks tool calls accessing sensitive paths', () => {
    const results = simulateScenario(
      [{ tool: 'read_file', args: { path: '/home/user/.ssh/id_rsa' } }],
      DEFAULT_POLICY,
    )

    expect(results).toHaveLength(1)
    expect(results[0].allowed).toBe(false)
    expect(results[0].findings.length).toBeGreaterThanOrEqual(1)
  })

  it('blocks disallowed tools when whitelist is set', () => {
    const policy: GatewayPolicy = {
      ...DEFAULT_POLICY,
      allowed_tools: ['read_file'],
    }

    const results = simulateScenario(
      [
        { tool: 'read_file', args: { path: '/project/ok.ts' } },
        { tool: 'execute_command', args: { command: 'ls' } },
      ],
      policy,
    )

    expect(results[0].allowed).toBe(true)
    expect(results[1].allowed).toBe(false)
  })

  it('simulates multiple calls in sequence', () => {
    const calls = [
      { tool: 'read_file', args: { path: '/project/app.ts' } },
      { tool: 'write_file', args: { path: '/project/out.ts', content: 'code' } },
      { tool: 'read_file', args: { path: '/etc/shadow' } },
    ]

    const results = simulateScenario(calls, DEFAULT_POLICY)
    expect(results).toHaveLength(3)
    expect(results[0].allowed).toBe(true)
    expect(results[1].allowed).toBe(true) // write_file requires approval but is not blocked
    expect(results[2].allowed).toBe(false) // /etc/shadow is blocked
  })
})

// ---------------------------------------------------------------------------
// parseJsonlLog
// ---------------------------------------------------------------------------

describe('parseJsonlLog', () => {
  it('parses valid JSONL content', () => {
    const content = [
      JSON.stringify({
        timestamp: '2026-03-30T10:00:00.000Z',
        direction: 'request',
        server: 'test',
        tool: 'read_file',
        args: { path: '/test' },
        blocked: false,
      }),
      JSON.stringify({
        timestamp: '2026-03-30T10:00:01.000Z',
        direction: 'response',
        server: 'test',
        tool: 'read_file',
        args: {},
        blocked: false,
      }),
    ].join('\n')

    const entries = parseJsonlLog(content)
    expect(entries).toHaveLength(2)
    expect(entries[0].tool).toBe('read_file')
    expect(entries[1].direction).toBe('response')
  })

  it('skips malformed lines', () => {
    const content = [
      '{"timestamp": "2026-03-30T10:00:00.000Z", "tool": "read_file"}',
      'not valid json',
      '{"timestamp": "2026-03-30T10:00:01.000Z", "tool": "list_files"}',
    ].join('\n')

    const entries = parseJsonlLog(content)
    expect(entries).toHaveLength(2)
  })

  it('skips entries without required fields', () => {
    const content = [
      '{"foo": "bar"}',
      '{"timestamp": "2026-03-30T10:00:00.000Z", "tool": "ok"}',
    ].join('\n')

    const entries = parseJsonlLog(content)
    expect(entries).toHaveLength(1)
    expect(entries[0].tool).toBe('ok')
  })

  it('handles empty input', () => {
    const entries = parseJsonlLog('')
    expect(entries).toHaveLength(0)
  })
})

// ---------------------------------------------------------------------------
// DEFAULT_POLICY
// ---------------------------------------------------------------------------

describe('DEFAULT_POLICY', () => {
  it('blocks common sensitive file patterns', () => {
    const sensitivePaths = [
      '/home/user/.ssh/id_rsa',
      '/home/user/.aws/credentials',
      '/project/.env',
      '/etc/shadow',
      '/etc/passwd',
      '/app/secrets.yaml',
      '/home/user/cert.pem',
      '/home/user/private.key',
    ]

    for (const path of sensitivePaths) {
      const match = matchesAnyPattern(path, DEFAULT_POLICY.blocked_paths)
      expect(match, `Expected "${path}" to be blocked`).toBeDefined()
    }
  })

  it('blocks cloud metadata endpoints', () => {
    const metadataUrls = [
      'http://169.254.169.254/latest/meta-data/',
      'http://metadata.google.internal/computeMetadata/v1/',
      'http://metadata.azure.com/metadata/instance',
    ]

    for (const url of metadataUrls) {
      const match = matchesAnyPattern(url, DEFAULT_POLICY.blocked_hosts)
      expect(match, `Expected "${url}" to be blocked`).toBeDefined()
    }
  })

  it('has rate limit of 60', () => {
    expect(DEFAULT_POLICY.rate_limit).toBe(60)
  })

  it('requires approval for destructive tools', () => {
    expect(DEFAULT_POLICY.require_approval).toContain('execute_command')
    expect(DEFAULT_POLICY.require_approval).toContain('write_file')
    expect(DEFAULT_POLICY.require_approval).toContain('delete_file')
  })
})
