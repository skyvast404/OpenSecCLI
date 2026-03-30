# MCP Integration

OpenSecCLI runs as an MCP (Model Context Protocol) server, exposing all 84 security commands as tools for AI agents.

## Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "opensec": {
      "command": "npx",
      "args": ["openseccli", "mcp"]
    }
  }
}
```

## Cursor

Add to `.cursor/mcp.json` in your project root:

```json
{
  "mcpServers": {
    "opensec": {
      "command": "npx",
      "args": ["openseccli", "mcp"]
    }
  }
}
```

## Docker

```json
{
  "mcpServers": {
    "opensec": {
      "command": "docker",
      "args": ["run", "-i", "--rm", "opensec", "mcp"]
    }
  }
}
```

## With API keys

Pass API keys via environment variables:

```json
{
  "mcpServers": {
    "opensec": {
      "command": "npx",
      "args": ["openseccli", "mcp"],
      "env": {
        "OPENSECCLI_VIRUSTOTAL_API_KEY": "your-key",
        "OPENSECCLI_ABUSEIPDB_API_KEY": "your-key",
        "OPENSECCLI_GREYNOISE_API_KEY": "your-key"
      }
    }
  }
}
```

## Available tools

Once connected, the AI agent can call any of the 84 commands. Examples:

| Tool | Description |
|------|-------------|
| `nvd_cve_get` | Look up CVE details |
| `nvd_cve_search` | Search CVEs by keyword |
| `enrichment_ip_enrich` | Multi-source IP threat intel |
| `vuln_header_audit` | Security header audit with grading |
| `vuln_cors_check` | CORS misconfiguration detection |
| `pentest_fuzz` | Parameter fuzzing |
| `agent_security_mcp_audit` | Audit MCP server tools |
| `scan_analyze` | Static analysis |

All tools return structured JSON. The AI agent can chain multiple tools together for complex investigations.

## How it works

```
AI Agent (Claude Desktop / Cursor / custom)
    |
    |-- MCP protocol (JSON-RPC over stdio)
    |
OpenSecCLI MCP Server
    |
    |-- Routes tool calls to opensec commands
    |-- Returns structured JSON results
```
