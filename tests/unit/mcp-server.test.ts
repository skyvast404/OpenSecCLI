import { describe, it, expect, beforeAll } from 'vitest'
import { handleMessage, registryToMcpTools } from '../../src/mcp-server.js'
import { cli } from '../../src/registry.js'
import { Strategy } from '../../src/types.js'

// Register a fake adapter so we have something in the registry for tests
beforeAll(() => {
  cli({
    provider: 'testprov',
    name: 'scan-host',
    description: 'Scan a host for open ports',
    strategy: Strategy.FREE,
    domain: 'recon',
    args: {
      target: { type: 'string', required: true, help: 'Target hostname or IP' },
      ports: { type: 'string', required: false, help: 'Port range', default: '1-1000' },
      fast: { type: 'boolean', required: false, help: 'Enable fast mode' },
    },
    columns: ['port', 'state', 'service'],
    func: async (_ctx, args) => {
      return [{ port: 80, state: 'open', service: 'http', target: args.target }]
    },
  })
})

describe('MCP Server', () => {
  describe('handleMessage — initialize', () => {
    it('returns protocol version, capabilities, and server info', async () => {
      const result = await handleMessage({
        jsonrpc: '2.0',
        id: 1,
        method: 'initialize',
        params: {
          protocolVersion: '2024-11-05',
          capabilities: {},
          clientInfo: { name: 'test-client', version: '1.0.0' },
        },
      })

      expect(result).toEqual({
        protocolVersion: '2024-11-05',
        capabilities: { tools: { listChanged: false } },
        serverInfo: { name: 'opensec', version: '0.2.0' },
      })
    })
  })

  describe('handleMessage — tools/list', () => {
    it('returns registered tools with correct schema', async () => {
      const result = (await handleMessage({
        jsonrpc: '2.0',
        id: 2,
        method: 'tools/list',
      })) as { tools: Array<{ name: string; description: string; inputSchema: Record<string, unknown> }> }

      expect(result.tools).toBeDefined()
      expect(Array.isArray(result.tools)).toBe(true)

      const scanTool = result.tools.find((t) => t.name === 'testprov_scan_host')
      expect(scanTool).toBeDefined()
      expect(scanTool!.description).toContain('recon')
      expect(scanTool!.description).toContain('Scan a host')
      expect(scanTool!.inputSchema.type).toBe('object')
      expect(scanTool!.inputSchema.required).toEqual(['target'])

      const props = scanTool!.inputSchema.properties as Record<string, { type: string }>
      expect(props.target.type).toBe('string')
      expect(props.ports.type).toBe('string')
      expect(props.fast.type).toBe('boolean')
    })
  })

  describe('handleMessage — tools/call', () => {
    it('executes a known command and returns results', async () => {
      const result = (await handleMessage({
        jsonrpc: '2.0',
        id: 3,
        method: 'tools/call',
        params: {
          name: 'testprov_scan_host',
          arguments: { target: '10.0.0.1' },
        },
      })) as { content: Array<{ type: string; text: string }> }

      expect(result.content).toHaveLength(1)
      expect(result.content[0].type).toBe('text')

      const parsed = JSON.parse(result.content[0].text)
      expect(parsed).toEqual([{ port: 80, state: 'open', service: 'http', target: '10.0.0.1' }])
    })

    it('returns isError for unknown commands', async () => {
      const result = (await handleMessage({
        jsonrpc: '2.0',
        id: 4,
        method: 'tools/call',
        params: {
          name: 'nonexistent_command',
          arguments: {},
        },
      })) as { content: Array<{ type: string; text: string }>; isError: boolean }

      expect(result.isError).toBe(true)
      const parsed = JSON.parse(result.content[0].text)
      expect(parsed.error).toBe(true)
      expect(parsed.message).toContain('Unknown command')
    })

    it('returns isError when command func throws', async () => {
      // Register a command that always throws
      cli({
        provider: 'testprov',
        name: 'fail-cmd',
        description: 'Always fails',
        strategy: Strategy.FREE,
        args: {},
        columns: [],
        func: async () => {
          throw new Error('Simulated failure')
        },
      })

      const result = (await handleMessage({
        jsonrpc: '2.0',
        id: 5,
        method: 'tools/call',
        params: {
          name: 'testprov_fail_cmd',
          arguments: {},
        },
      })) as { content: Array<{ type: string; text: string }>; isError: boolean }

      expect(result.isError).toBe(true)
      const parsed = JSON.parse(result.content[0].text)
      expect(parsed.error).toBe(true)
      expect(parsed.message).toBe('Simulated failure')
    })
  })

  describe('handleMessage — notifications', () => {
    it('returns null for notifications/initialized', async () => {
      const result = await handleMessage({
        jsonrpc: '2.0',
        method: 'notifications/initialized',
      })
      expect(result).toBeNull()
    })

    it('returns null for notifications/cancelled', async () => {
      const result = await handleMessage({
        jsonrpc: '2.0',
        method: 'notifications/cancelled',
      })
      expect(result).toBeNull()
    })
  })

  describe('handleMessage — unknown method', () => {
    it('returns method-not-found error', async () => {
      const result = (await handleMessage({
        jsonrpc: '2.0',
        id: 6,
        method: 'unknown/method',
      })) as { error: { code: number; message: string } }

      expect(result.error).toBeDefined()
      expect(result.error.code).toBe(-32601)
      expect(result.error.message).toContain('Method not found')
    })
  })

  describe('registryToMcpTools', () => {
    it('converts arg choices to enum in schema', () => {
      cli({
        provider: 'testprov',
        name: 'with-choices',
        description: 'Has choices',
        strategy: Strategy.FREE,
        args: {
          severity: {
            type: 'string',
            required: false,
            help: 'Filter severity',
            choices: ['low', 'medium', 'high', 'critical'],
          },
        },
        columns: [],
        func: async () => [],
      })

      const tools = registryToMcpTools()
      const choiceTool = tools.find((t) => t.name === 'testprov_with_choices')
      expect(choiceTool).toBeDefined()
      expect(choiceTool!.inputSchema.properties.severity.enum).toEqual([
        'low',
        'medium',
        'high',
        'critical',
      ])
    })
  })
})
