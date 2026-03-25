/**
 * Enrich pipeline step — multi-source parallel query with field extraction.
 * Queries N APIs via Promise.all, extracts specified fields, returns merged results.
 */

import { renderTemplate, renderObject } from '../template.js'

interface EnrichSource {
  name: string
  url: string
  method?: string
  headers?: Record<string, string>
  params?: Record<string, string>
  select?: string
  fields: Record<string, string>
}

interface EnrichParams {
  sources: EnrichSource[]
  timeout?: number
}

interface StepContext {
  args: Record<string, unknown>
  auth: Record<string, unknown>
}

export async function executeEnrich(
  params: EnrichParams,
  _data: unknown,
  ctx: StepContext,
): Promise<Record<string, unknown>[]> {
  const timeout = (params.timeout ?? 10) * 1000
  const templateCtx = { args: ctx.args, auth: ctx.auth }

  const promises = params.sources.map(async (source): Promise<Record<string, unknown>> => {
    try {
      const url = renderTemplate(source.url, templateCtx)
      const headers = (renderObject(source.headers ?? {}, templateCtx) ?? {}) as Record<string, string>
      const queryParams = (renderObject(source.params ?? {}, templateCtx) ?? {}) as Record<string, string>

      const fullUrl = new URL(url)
      for (const [k, v] of Object.entries(queryParams)) {
        if (v) fullUrl.searchParams.set(k, String(v))
      }

      const response = await fetch(fullUrl.toString(), {
        method: (source.method ?? 'GET').toUpperCase(),
        headers: { Accept: 'application/json', ...headers },
        signal: AbortSignal.timeout(timeout),
      })

      if (!response.ok) {
        return { source: source.name, status: 'error', error: `HTTP ${response.status}` }
      }

      let data = await response.json()

      // Select nested path if specified
      if (source.select) {
        data = walkPath(data, source.select.split('.'))
      }

      // Extract fields
      const row: Record<string, unknown> = { source: source.name, status: 'ok' }
      for (const [outputField, dataPath] of Object.entries(source.fields)) {
        row[outputField] = walkPath(data, dataPath.split('.'))
      }

      return row
    } catch (error) {
      return {
        source: source.name,
        status: 'error',
        error: (error as Error).message,
      }
    }
  })

  return Promise.all(promises)
}

function walkPath(value: unknown, segments: string[]): unknown {
  for (const segment of segments) {
    if (value === null || value === undefined) return undefined
    if (Array.isArray(value) && /^\d+$/.test(segment)) {
      value = value[parseInt(segment, 10)]
    } else if (typeof value === 'object') {
      value = (value as Record<string, unknown>)[segment]
    } else {
      return undefined
    }
  }
  return value
}
