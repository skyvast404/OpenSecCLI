/**
 * Output parsers for reconnaissance tools.
 */

import { parseJsonLines, parseTextLines } from '../_utils/tool-runner.js'

export function parseSubfinderOutput(stdout: string): Record<string, unknown>[] {
  // Try JSONL first (subfinder -json)
  const jsonResults = parseJsonLines(stdout)
  if (jsonResults.length > 0) {
    return jsonResults.map((r) => ({
      subdomain: r.host as string,
      source: (r.source as string) ?? 'subfinder',
    }))
  }
  // Fallback: plain text (amass, one domain per line)
  return parseTextLines(stdout).map((line) => ({
    subdomain: line,
    source: 'amass',
  }))
}

export function parseHttpxOutput(stdout: string): Record<string, unknown>[] {
  return parseJsonLines(stdout).map((r) => ({
    url: r.url ?? r.input,
    status: r.status_code ?? r['status-code'],
    title: r.title ?? '',
    technologies: Array.isArray(r.tech) ? (r.tech as string[]).join(', ') : '',
    server: r.webserver ?? '',
    content_length: r.content_length ?? r['content-length'] ?? 0,
  }))
}

export function parseNmapOutput(xml: string): Record<string, unknown>[] {
  const results: Record<string, unknown>[] = []
  // Simple regex-based XML parser for nmap output
  const hostPattern = /<host[\s\S]*?<\/host>/g
  const addrPattern = /<address addr="([^"]+)"/
  const portPattern = /<port protocol="([^"]+)" portid="(\d+)">\s*<state state="([^"]+)"\/>\s*(?:<service name="([^"]*)"(?:\s+product="([^"]*)")?(?:\s+version="([^"]*)")?)?/g

  let hostMatch
  while ((hostMatch = hostPattern.exec(xml)) !== null) {
    const hostXml = hostMatch[0]
    const addrMatch = addrPattern.exec(hostXml)
    const ip = addrMatch?.[1] ?? 'unknown'

    let portMatch
    const portRegex = new RegExp(portPattern.source, 'g')
    while ((portMatch = portRegex.exec(hostXml)) !== null) {
      results.push({
        ip,
        port: parseInt(portMatch[2], 10),
        protocol: portMatch[1],
        state: portMatch[3],
        service: portMatch[4] ?? '',
        product: portMatch[5] ?? '',
        version: portMatch[6] ?? '',
      })
    }
  }
  return results
}

export function parseFfufOutput(stdout: string): Record<string, unknown>[] {
  try {
    const output = JSON.parse(stdout) as { results?: Array<Record<string, unknown>> }
    return (output.results ?? []).map((r) => ({
      url: r.url ?? (r.input as Record<string, unknown> | undefined)?.FUZZ,
      status: r.status,
      length: r.length,
      words: r.words,
      lines: r.lines,
    }))
  } catch {
    // Fallback: parse text output
    return parseTextLines(stdout)
      .filter((line) => line.includes('Status:'))
      .map((line) => ({ url: line, status: 0, length: 0 }))
  }
}
