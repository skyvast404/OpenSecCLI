/**
 * Transform pipeline steps: select, map, filter, sort, limit.
 * Mirrors OpenCLI's transform steps.
 */

import { renderObject, evaluateExpression } from '../template.js'

interface StepContext {
  args: Record<string, unknown>
  auth: Record<string, unknown>
}

/** select — extract nested path from data */
export function executeSelect(
  params: { path: string },
  data: unknown,
): unknown {
  if (!params.path || params.path === '') return data

  const segments = params.path.split('.')
  let value: unknown = data

  for (const segment of segments) {
    if (value === null || value === undefined) return null
    if (Array.isArray(value) && /^\d+$/.test(segment)) {
      value = value[parseInt(segment, 10)]
    } else if (typeof value === 'object') {
      value = (value as Record<string, unknown>)[segment]
    } else {
      return null
    }
  }

  return value
}

/** map — transform each item using a template */
export function executeMap(
  params: { template: Record<string, string>; select?: string },
  data: unknown,
  ctx: StepContext,
): unknown[] {
  let items = params.select ? executeSelect({ path: params.select }, data) : data

  if (!Array.isArray(items)) {
    items = items ? [items] : []
  }

  return (items as unknown[]).map((item, index) => {
    const templateCtx = { args: ctx.args, auth: ctx.auth, item, index }
    const result: Record<string, unknown> = {}

    for (const [key, expr] of Object.entries(params.template)) {
      result[key] = renderObject(expr, templateCtx)
    }

    return result
  })
}

/** filter — keep items matching a condition */
export function executeFilter(
  params: { condition: string },
  data: unknown,
  ctx: StepContext,
): unknown[] {
  if (!Array.isArray(data)) return data ? [data] : []

  return data.filter((item, index) => {
    const templateCtx = { args: ctx.args, auth: ctx.auth, item, index }
    return evaluateExpression(params.condition.replace(/\{\{\s*|\s*\}\}/g, ''), templateCtx)
  })
}

/** sort — order items by a field */
export function executeSort(
  params: { key: string; reverse?: boolean },
  data: unknown,
): unknown[] {
  if (!Array.isArray(data)) return data ? [data] : []

  const sorted = [...data].sort((a, b) => {
    const aVal = (a as Record<string, unknown>)[params.key]
    const bVal = (b as Record<string, unknown>)[params.key]

    if (typeof aVal === 'number' && typeof bVal === 'number') {
      return aVal - bVal
    }
    return String(aVal ?? '').localeCompare(String(bVal ?? ''))
  })

  return params.reverse ? sorted.reverse() : sorted
}

/** limit — truncate array to N items */
export function executeLimit(
  params: { count: string | number },
  data: unknown,
  ctx: StepContext,
): unknown[] {
  if (!Array.isArray(data)) return data ? [data] : []

  let count: number
  if (typeof params.count === 'number') {
    count = params.count
  } else {
    const templateCtx = { args: ctx.args, auth: ctx.auth }
    const rendered = renderObject(params.count, templateCtx)
    count = Number(rendered)
  }

  return data.slice(0, count)
}
