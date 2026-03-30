#!/usr/bin/env node
/**
 * OpenSecCLI MCP Server
 * Exposes opensec commands as MCP tools for AI agents.
 *
 * Usage in Claude Desktop config:
 * {
 *   "mcpServers": {
 *     "opensec": {
 *       "command": "opensec",
 *       "args": ["mcp"]
 *     }
 *   }
 * }
 */

import { getRegistry } from './registry.js'
import { discoverAdapters } from './discovery.js'
import * as readline from 'node:readline'

interface McpTool {
  name: string
  description: string
  inputSchema: {
    type: 'object'
    properties: Record<string, { type: string; description?: string; enum?: string[] }>
    required: string[]
  }
}

interface JsonRpcRequest {
  jsonrpc: string
  id?: number | string | null
  method: string
  params?: Record<string, unknown>
}

interface JsonRpcResponse {
  jsonrpc: '2.0'
  id: number | string | null
  result?: unknown
  error?: { code: number; message: string }
}

/** Convert registry commands to MCP tool definitions. */
export function registryToMcpTools(): McpTool[] {
  const registry = getRegistry()
  const tools: McpTool[] = []

  for (const [key, cmd] of registry) {
    // Convert "vuln/header-audit" to "vuln_header_audit" (MCP tool names can't have slashes)
    const toolName = key.replace('/', '_').replace(/-/g, '_')

    const properties: Record<string, { type: string; description?: string; enum?: string[] }> = {}
    const required: string[] = []

    for (const [argName, argDef] of Object.entries(cmd.args)) {
      const prop: { type: string; description?: string; enum?: string[] } = {
        type: argDef.type === 'number' ? 'number' : argDef.type === 'boolean' ? 'boolean' : 'string',
        description: argDef.help ?? argName,
      }
      if (argDef.choices) {
        prop.enum = argDef.choices
      }
      properties[argName] = prop
      if (argDef.required) {
        required.push(argName)
      }
    }

    tools.push({
      name: toolName,
      description: `[${cmd.domain ?? cmd.provider}] ${cmd.description}`,
      inputSchema: { type: 'object', properties, required },
    })
  }

  return tools
}

/** Handle a single MCP JSON-RPC message and return the result payload (or null for notifications). */
export async function handleMessage(msg: JsonRpcRequest): Promise<unknown> {
  switch (msg.method) {
    case 'initialize':
      return {
        protocolVersion: '2024-11-05',
        capabilities: { tools: { listChanged: false } },
        serverInfo: { name: 'opensec', version: '0.2.0' },
      }

    case 'tools/list':
      return { tools: registryToMcpTools() }

    case 'tools/call': {
      const params = msg.params ?? {}
      const toolName = params.name as string
      const args = (params.arguments ?? {}) as Record<string, unknown>

      // Convert tool name back: "vuln_header_audit" -> "vuln/header-audit"
      const parts = toolName.split('_')
      const provider = parts[0]
      const name = parts.slice(1).join('-')
      const commandId = `${provider}/${name}`

      const registry = getRegistry()
      const cmd = registry.get(commandId)

      if (!cmd) {
        return {
          content: [{ type: 'text', text: JSON.stringify({ error: true, message: `Unknown command: ${commandId}` }) }],
          isError: true,
        }
      }

      try {
        const ctx = {
          auth: null,
          args,
          log: {
            info() { /* noop */ },
            warn() { /* noop */ },
            error() { /* noop */ },
            verbose() { /* noop */ },
            debug() { /* noop */ },
            step() { /* noop */ },
          },
        }
        const result = cmd.func
          ? await cmd.func(ctx, args)
          : [] // pipeline commands need different handling

        return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] }
      } catch (err) {
        return {
          content: [{ type: 'text', text: JSON.stringify({ error: true, message: (err as Error).message }) }],
          isError: true,
        }
      }
    }

    case 'notifications/initialized':
    case 'notifications/cancelled':
      return null // no response needed for notifications

    default:
      return { error: { code: -32601, message: `Method not found: ${msg.method}` } }
  }
}

/** Start the MCP server, reading JSON-RPC messages from stdin and writing responses to stdout. */
export async function startMcpServer(): Promise<void> {
  await discoverAdapters()

  const rl = readline.createInterface({ input: process.stdin })

  rl.on('line', async (line: string) => {
    try {
      const msg: JsonRpcRequest = JSON.parse(line)
      const result = await handleMessage(msg)

      if (result === null) return // notifications don't need responses

      const response: JsonRpcResponse = { jsonrpc: '2.0', id: msg.id ?? null, result }
      process.stdout.write(JSON.stringify(response) + '\n')
    } catch {
      const response: JsonRpcResponse = {
        jsonrpc: '2.0',
        id: null,
        error: { code: -32700, message: 'Parse error' },
      }
      process.stdout.write(JSON.stringify(response) + '\n')
    }
  })
}
