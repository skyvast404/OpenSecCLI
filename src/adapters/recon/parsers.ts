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

  // Extract each <host>...</host> block
  const hostBlocks = xml.match(/<host[\s\S]*?<\/host>/g) ?? []

  for (const hostXml of hostBlocks) {
    // Extract IP address
    const ipMatch = hostXml.match(/<address\s+addr="([^"]+)"/)
    const ip = ipMatch?.[1] ?? 'unknown'

    // Extract each <port> block (handle both <port>...</port> and self-closing)
    const portBlocks = hostXml.match(/<port\s[^>]*>[\s\S]*?<\/port>/g) ?? []

    for (const portXml of portBlocks) {
      const protoMatch = portXml.match(/protocol="([^"]+)"/)
      const portIdMatch = portXml.match(/portid="(\d+)"/)
      const stateMatch = portXml.match(/<state\s+state="([^"]+)"/)
      const serviceNameMatch = portXml.match(/<service\s[^>]*name="([^"]*)"/)
      const productMatch = portXml.match(/product="([^"]*)"/)
      const versionMatch = portXml.match(/version="([^"]*)"/)

      results.push({
        ip,
        port: parseInt(portIdMatch?.[1] ?? '0', 10),
        protocol: protoMatch?.[1] ?? 'tcp',
        state: stateMatch?.[1] ?? 'unknown',
        service: serviceNameMatch?.[1] ?? '',
        product: productMatch?.[1] ?? '',
        version: versionMatch?.[1] ?? '',
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
