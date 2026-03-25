/**
 * HTTP request pipeline step.
 * Mirrors OpenCLI's fetch step — single + batch requests with concurrency.
 */

import { PipelineError } from '../../errors.js'
import { renderTemplate, renderObject } from '../template.js'

interface RequestParams {
  url: string
  method?: string
  headers?: Record<string, string>
  params?: Record<string, string>
  body?: unknown
  concurrency?: number
  timeout?: number
}

interface StepContext {
  args: Record<string, unknown>
  auth: Record<string, unknown>
}

export async function executeRequest(
  params: RequestParams,
  data: unknown,
  ctx: StepContext,
): Promise<unknown> {
  const templateCtx = { args: ctx.args, auth: ctx.auth, data }

  // If data is an array and URL contains {{ item }}, do batch requests
  if (Array.isArray(data) && params.url.includes('{{ item')) {
    return executeBatch(params, data, ctx)
  }

  const url = buildUrl(
    renderTemplate(params.url, templateCtx),
    renderObject(params.params ?? {}, templateCtx) as Record<string, string>,
  )

  const headers = renderObject(params.headers ?? {}, templateCtx) as Record<string, string>
  const method = (params.method ?? 'GET').toUpperCase()

  const fetchOptions: RequestInit = {
    method,
    headers: {
      'Accept': 'application/json',
      ...headers,
    },
    signal: AbortSignal.timeout((params.timeout ?? 30) * 1000),
  }

  if (method !== 'GET' && method !== 'HEAD' && params.body) {
    const body = renderObject(params.body, templateCtx)
    fetchOptions.body = JSON.stringify(body)
    fetchOptions.headers = {
      ...fetchOptions.headers as Record<string, string>,
      'Content-Type': 'application/json',
    }
  }

  const response = await fetch(url, fetchOptions)

  if (!response.ok) {
    throw new PipelineError(
      'request',
      `HTTP ${response.status} ${response.statusText} from ${url}`,
    )
  }

  const contentType = response.headers.get('content-type') ?? ''
  if (contentType.includes('json')) {
    return response.json()
  }
  return response.text()
}

async function executeBatch(
  params: RequestParams,
  items: unknown[],
  ctx: StepContext,
): Promise<unknown[]> {
  const concurrency = params.concurrency ?? 5
  const results: unknown[] = []

  for (let i = 0; i < items.length; i += concurrency) {
    const batch = items.slice(i, i + concurrency)
    const promises = batch.map((item, idx) => {
      const templateCtx = {
        args: ctx.args,
        auth: ctx.auth,
        item,
        index: i + idx,
      }

      const url = buildUrl(
        renderTemplate(params.url, templateCtx),
        renderObject(params.params ?? {}, templateCtx) as Record<string, string>,
      )

      const headers = renderObject(params.headers ?? {}, templateCtx) as Record<string, string>

      return fetch(url, {
        method: (params.method ?? 'GET').toUpperCase(),
        headers: { 'Accept': 'application/json', ...headers },
        signal: AbortSignal.timeout((params.timeout ?? 30) * 1000),
      }).then(r => r.ok ? r.json() : null)
    })

    const batchResults = await Promise.all(promises)
    results.push(...batchResults.filter(r => r !== null))
  }

  return results
}

function buildUrl(base: string, params: Record<string, string>): string {
  const url = new URL(base)
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null && value !== '') {
      url.searchParams.set(key, String(value))
    }
  }
  return url.toString()
}
