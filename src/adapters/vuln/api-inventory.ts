/**
 * API endpoint inventory adapter.
 * Discovers and inventories API endpoints from OpenAPI specs or JS bundles.
 * Pure TypeScript — no external tools required.
 */

import { cli, Strategy } from '../../registry.js'
import type { ExecContext } from '../../types.js'
import { readFile } from 'node:fs/promises'

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface ApiEndpoint {
  method: string
  path: string
  auth_required: boolean
  parameters: string
  description: string
  [key: string]: unknown
}

interface OpenApiPathItem {
  readonly summary?: string
  readonly description?: string
  readonly security?: readonly Record<string, readonly string[]>[]
  readonly parameters?: readonly OpenApiParameter[]
}

interface OpenApiParameter {
  readonly name: string
  readonly in: string
  readonly required?: boolean
  readonly description?: string
}

interface OpenApiSpec {
  readonly openapi?: string
  readonly swagger?: string
  readonly paths?: Record<string, Record<string, OpenApiPathItem>>
  readonly info?: { readonly title?: string; readonly version?: string }
}

// ---------------------------------------------------------------------------
// OpenAPI/Swagger parser
// ---------------------------------------------------------------------------

export function parseOpenApiSpec(content: string): readonly ApiEndpoint[] {
  let spec: OpenApiSpec

  try {
    spec = JSON.parse(content) as OpenApiSpec
  } catch {
    // Try YAML-like simple parsing for basic cases
    throw new Error('Failed to parse spec as JSON. Ensure the file is valid JSON or OpenAPI format.')
  }

  if (!spec.paths) {
    return []
  }

  const endpoints: ApiEndpoint[] = []
  const httpMethods = ['get', 'post', 'put', 'patch', 'delete', 'head', 'options', 'trace']

  for (const [path, pathItem] of Object.entries(spec.paths)) {
    for (const [method, operation] of Object.entries(pathItem)) {
      if (!httpMethods.includes(method.toLowerCase())) {
        continue
      }

      const op = operation as OpenApiPathItem
      const params = op.parameters ?? []
      const paramStr = params
        .map((p) => `${p.name}(${p.in}${p.required ? ',required' : ''})`)
        .join(', ')

      const authRequired = hasSecurityRequirement(op)

      endpoints.push({
        method: method.toUpperCase(),
        path,
        auth_required: authRequired,
        parameters: paramStr || 'none',
        description: op.summary ?? op.description ?? '',
      })
    }
  }

  return endpoints
}

function hasSecurityRequirement(operation: OpenApiPathItem): boolean {
  if (!operation.security) {
    return false
  }
  return operation.security.length > 0 &&
    operation.security.some((s) => Object.keys(s).length > 0)
}

// ---------------------------------------------------------------------------
// URL-based API discovery (JS bundle scanning)
// ---------------------------------------------------------------------------

const API_PATH_PATTERN = /(?:["'`])(\/?(?:api|v[0-9]+|rest|graphql)\/[a-zA-Z0-9_/\-{}:.]+)(?:["'`])/g
const FETCH_PATTERN = /fetch\s*\(\s*["'`]([^"'`]+)["'`]/g
const AXIOS_PATTERN = /axios\.\w+\s*\(\s*["'`]([^"'`]+)["'`]/g
const XHR_PATTERN = /\.open\s*\(\s*["'`](?:GET|POST|PUT|PATCH|DELETE)["'`]\s*,\s*["'`]([^"'`]+)["'`]/g

export function extractApiUrlsFromJs(jsContent: string): readonly ApiEndpoint[] {
  const discoveredPaths = new Set<string>()

  const patterns = [API_PATH_PATTERN, FETCH_PATTERN, AXIOS_PATTERN, XHR_PATTERN]

  for (const pattern of patterns) {
    const regex = new RegExp(pattern.source, pattern.flags)
    let match: RegExpExecArray | null
    while ((match = regex.exec(jsContent)) !== null) {
      const path = match[1]
      if (path && isApiPath(path)) {
        discoveredPaths.add(normalizePath(path))
      }
    }
  }

  return [...discoveredPaths].map((path) => ({
    method: inferMethod(path),
    path,
    auth_required: false,
    parameters: extractPathParams(path),
    description: 'Discovered from JS bundle',
  }))
}

function isApiPath(path: string): boolean {
  if (path.length < 3 || path.length > 500) return false
  if (path.endsWith('.js') || path.endsWith('.css') || path.endsWith('.png')) return false
  if (path.endsWith('.svg') || path.endsWith('.jpg') || path.endsWith('.gif')) return false
  if (path.endsWith('.woff') || path.endsWith('.woff2') || path.endsWith('.ttf')) return false

  return /(?:api|v[0-9]+|rest|graphql)/i.test(path)
}

function normalizePath(path: string): string {
  // Remove leading protocol/domain if present
  const cleaned = path.replace(/^https?:\/\/[^/]+/, '')
  return cleaned.startsWith('/') ? cleaned : `/${cleaned}`
}

function inferMethod(path: string): string {
  // Heuristic: paths that look like resource creation/mutation
  if (/\/create|\/add|\/new|\/register|\/signup/i.test(path)) return 'POST'
  if (/\/update|\/edit|\/modify/i.test(path)) return 'PUT'
  if (/\/delete|\/remove/i.test(path)) return 'DELETE'
  return 'GET'
}

function extractPathParams(path: string): string {
  const params: string[] = []
  const paramPattern = /\{([^}]+)\}|:([a-zA-Z_]+)/g
  let match: RegExpExecArray | null
  while ((match = paramPattern.exec(path)) !== null) {
    const name = match[1] ?? match[2]
    params.push(`${name}(path,required)`)
  }
  return params.length > 0 ? params.join(', ') : 'none'
}

// ---------------------------------------------------------------------------
// Source detection
// ---------------------------------------------------------------------------

function isUrl(source: string): boolean {
  return source.startsWith('http://') || source.startsWith('https://')
}

async function readLocalFile(path: string): Promise<string> {
  return readFile(path, 'utf-8')
}

function detectFormat(
  content: string,
  formatType: string,
): 'openapi' | 'swagger' | 'har' | 'unknown' {
  if (formatType !== 'auto') {
    return formatType as 'openapi' | 'swagger' | 'har'
  }

  try {
    const parsed = JSON.parse(content) as Record<string, unknown>
    if (parsed.openapi) return 'openapi'
    if (parsed.swagger) return 'swagger'
    if (parsed.log && typeof parsed.log === 'object') return 'har'
  } catch {
    // Not JSON
  }

  return 'unknown'
}

// ---------------------------------------------------------------------------
// HAR file parser
// ---------------------------------------------------------------------------

interface HarEntry {
  readonly request: {
    readonly method: string
    readonly url: string
    readonly queryString?: readonly { readonly name: string }[]
  }
}

interface HarLog {
  readonly log: {
    readonly entries: readonly HarEntry[]
  }
}

function parseHarFile(content: string): readonly ApiEndpoint[] {
  const har = JSON.parse(content) as HarLog
  if (!har.log?.entries) return []

  const seenPaths = new Set<string>()
  const endpoints: ApiEndpoint[] = []

  for (const entry of har.log.entries) {
    const urlObj = new URL(entry.request.url)
    const path = urlObj.pathname
    const key = `${entry.request.method}:${path}`

    if (seenPaths.has(key)) continue
    seenPaths.add(key)

    if (!isApiPath(path)) continue

    const params = (entry.request.queryString ?? [])
      .map((q) => `${q.name}(query)`)
      .join(', ')

    endpoints.push({
      method: entry.request.method,
      path,
      auth_required: false,
      parameters: params || 'none',
      description: 'Discovered from HAR file',
    })
  }

  return endpoints
}

// ---------------------------------------------------------------------------
// Adapter registration
// ---------------------------------------------------------------------------

cli({
  provider: 'vuln',
  name: 'api-inventory',
  description: 'Discover and inventory API endpoints from OpenAPI specs or JS bundles',
  strategy: Strategy.FREE,
  domain: 'vuln-scan',
  args: {
    source: {
      type: 'string',
      required: true,
      help: 'Path to OpenAPI/Swagger spec OR URL to scan for JS bundles',
    },
    format_type: {
      type: 'string',
      required: false,
      default: 'auto',
      choices: ['auto', 'openapi', 'swagger', 'har'],
      help: 'Source format',
    },
  },
  columns: ['method', 'path', 'auth_required', 'parameters', 'description'],

  async func(ctx: ExecContext, args: Record<string, unknown>) {
    const source = args.source as string
    const formatType = (args.format_type as string) ?? 'auto'

    if (isUrl(source)) {
      ctx.log.info(`Fetching ${source} for API discovery...`)
      const response = await fetch(source, {
        signal: AbortSignal.timeout(30_000),
      })
      const html = await response.text()

      // Try to parse as OpenAPI spec first
      const format = detectFormat(html, formatType)
      if (format === 'openapi' || format === 'swagger') {
        const endpoints = parseOpenApiSpec(html)
        ctx.log.info(`Found ${endpoints.length} endpoints from OpenAPI spec`)
        return [...endpoints]
      }

      if (format === 'har') {
        const endpoints = parseHarFile(html)
        ctx.log.info(`Found ${endpoints.length} endpoints from HAR file`)
        return [...endpoints]
      }

      // Extract API URLs from HTML/JS content
      const endpoints = extractApiUrlsFromJs(html)

      // Also look for script src tags and fetch those
      const scriptSrcPattern = /<script[^>]+src=["']([^"']+\.js[^"']*)["']/g
      const scriptUrls: string[] = []
      let match: RegExpExecArray | null
      while ((match = scriptSrcPattern.exec(html)) !== null) {
        const scriptUrl = match[1]
        if (scriptUrl.startsWith('http')) {
          scriptUrls.push(scriptUrl)
        } else if (scriptUrl.startsWith('/')) {
          const baseUrl = new URL(source)
          scriptUrls.push(`${baseUrl.origin}${scriptUrl}`)
        }
      }

      const additionalEndpoints: ApiEndpoint[] = []
      for (const scriptUrl of scriptUrls.slice(0, 10)) {
        try {
          const jsResponse = await fetch(scriptUrl, {
            signal: AbortSignal.timeout(15_000),
          })
          const jsContent = await jsResponse.text()
          const jsEndpoints = extractApiUrlsFromJs(jsContent)
          additionalEndpoints.push(...jsEndpoints)
        } catch {
          ctx.log.debug(`Failed to fetch JS bundle: ${scriptUrl}`)
        }
      }

      const allEndpoints = deduplicateEndpoints([...endpoints, ...additionalEndpoints])
      ctx.log.info(`Found ${allEndpoints.length} API endpoints from JS bundles`)
      return [...allEndpoints]
    }

    // Local file
    ctx.log.info(`Reading ${source}...`)
    const content = await readLocalFile(source)
    const format = detectFormat(content, formatType)

    if (format === 'har') {
      const endpoints = parseHarFile(content)
      ctx.log.info(`Found ${endpoints.length} endpoints from HAR file`)
      return [...endpoints]
    }

    if (format === 'openapi' || format === 'swagger') {
      const endpoints = parseOpenApiSpec(content)
      ctx.log.info(`Found ${endpoints.length} endpoints from spec`)
      return [...endpoints]
    }

    // Try parsing as OpenAPI anyway
    try {
      const endpoints = parseOpenApiSpec(content)
      if (endpoints.length > 0) {
        ctx.log.info(`Found ${endpoints.length} endpoints`)
        return [...endpoints]
      }
    } catch {
      // Not an OpenAPI spec
    }

    // Try as JS content
    const endpoints = extractApiUrlsFromJs(content)
    ctx.log.info(`Found ${endpoints.length} endpoints from JS analysis`)
    return [...endpoints]
  },
})

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function deduplicateEndpoints(
  endpoints: readonly ApiEndpoint[],
): readonly ApiEndpoint[] {
  const seen = new Set<string>()
  const result: ApiEndpoint[] = []

  for (const ep of endpoints) {
    const key = `${ep.method}:${ep.path}`
    if (!seen.has(key)) {
      seen.add(key)
      result.push(ep)
    }
  }

  return result
}
