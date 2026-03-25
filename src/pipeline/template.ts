/**
 * Template expression engine for {{ }} expressions in YAML adapters.
 * Mirrors OpenCLI's template system — sandboxed evaluation.
 */

const BLOCKED_PATTERNS = /constructor|prototype|__proto__|process|require|import|eval|Function/

const MAX_EXPR_LENGTH = 2000

interface TemplateContext {
  args: Record<string, unknown>
  auth: Record<string, unknown>
  item?: unknown
  index?: number
  data?: unknown
}

export function renderTemplate(template: string, ctx: TemplateContext): string {
  return template.replace(/\{\{\s*(.+?)\s*\}\}/g, (_, expr: string) => {
    const result = evaluateExpression(expr.trim(), ctx)
    if (result === null || result === undefined) return ''
    return String(result)
  })
}

export function evaluateExpression(expr: string, ctx: TemplateContext): unknown {
  if (expr.length > MAX_EXPR_LENGTH) {
    throw new Error(`Expression too long (${expr.length} > ${MAX_EXPR_LENGTH})`)
  }

  if (BLOCKED_PATTERNS.test(expr)) {
    throw new Error(`Blocked pattern in expression: ${expr}`)
  }

  // Handle filter chains: item.tags | join(', ')
  // Split on single | only (not ||)
  const parts = expr.split(/(?<!\|)\|(?!\|)/).map(p => p.trim())
  let value = resolveValue(parts[0], ctx)

  for (let i = 1; i < parts.length; i++) {
    value = applyFilter(parts[i], value)
  }

  return value
}

function resolveValue(expr: string, ctx: TemplateContext): unknown {
  // Handle ternary: condition ? a : b
  const ternaryMatch = expr.match(/^(.+?)\s*\?\s*(.+?)\s*:\s*(.+)$/)
  if (ternaryMatch) {
    const condition = resolveValue(ternaryMatch[1], ctx)
    return condition
      ? resolveValue(ternaryMatch[2].trim(), ctx)
      : resolveValue(ternaryMatch[3].trim(), ctx)
  }

  // Handle comparison: item.score > 80
  const compMatch = expr.match(/^(.+?)\s*(===|!==|==|!=|>=|<=|>|<)\s*(.+)$/)
  if (compMatch) {
    const left = resolveValue(compMatch[1].trim(), ctx)
    const right = resolveValue(compMatch[3].trim(), ctx)
    return compare(left, right, compMatch[2])
  }

  // Handle logical OR: value || 'default'
  const orMatch = expr.match(/^(.+?)\s*\|\|\s*(.+)$/)
  if (orMatch) {
    const left = resolveValue(orMatch[1].trim(), ctx)
    if (left) return left
    return resolveValue(orMatch[2].trim(), ctx)
  }

  // Handle arithmetic: index + 1
  const addMatch = expr.match(/^(.+?)\s*([+\-*])\s*(\d+)$/)
  if (addMatch) {
    const left = Number(resolveValue(addMatch[1].trim(), ctx))
    const right = Number(addMatch[3])
    switch (addMatch[2]) {
      case '+': return left + right
      case '-': return left - right
      case '*': return left * right
    }
  }

  // String literal: 'hello' or "hello"
  const strMatch = expr.match(/^['"](.*)['"]$/)
  if (strMatch) return strMatch[1]

  // Number literal
  if (/^-?\d+(\.\d+)?$/.test(expr)) return Number(expr)

  // Boolean literal
  if (expr === 'true') return true
  if (expr === 'false') return false
  if (expr === 'null') return null

  // Dot-notation path resolution
  return resolvePath(expr, ctx)
}

function resolvePath(path: string, ctx: TemplateContext): unknown {
  const segments = path.split('.')
  const root = segments[0]

  let value: unknown
  switch (root) {
    case 'args':
      value = ctx.args
      break
    case 'auth':
      value = ctx.auth
      break
    case 'item':
      value = ctx.item
      break
    case 'index':
      return ctx.index
    case 'data':
      value = ctx.data
      break
    default:
      // Try item first, then ctx directly
      if (ctx.item && typeof ctx.item === 'object' && root in (ctx.item as Record<string, unknown>)) {
        value = ctx.item
        return walkPath(value, segments)
      }
      return undefined
  }

  return walkPath(value, segments.slice(1))
}

function walkPath(value: unknown, segments: string[]): unknown {
  for (const segment of segments) {
    if (value === null || value === undefined) return undefined
    if (typeof value === 'object') {
      value = (value as Record<string, unknown>)[segment]
    } else {
      return undefined
    }
  }
  return value
}

function compare(left: unknown, right: unknown, op: string): boolean {
  switch (op) {
    case '===':
    case '==': return left == right
    case '!==':
    case '!=': return left != right
    case '>': return Number(left) > Number(right)
    case '<': return Number(left) < Number(right)
    case '>=': return Number(left) >= Number(right)
    case '<=': return Number(left) <= Number(right)
    default: return false
  }
}

function applyFilter(filterExpr: string, value: unknown): unknown {
  const match = filterExpr.match(/^(\w+)(?:\((.+)\))?$/)
  if (!match) return value

  const [, name, rawArg] = match
  const arg = rawArg?.replace(/^['"]|['"]$/g, '')

  switch (name) {
    case 'upper': return String(value).toUpperCase()
    case 'lower': return String(value).toLowerCase()
    case 'trim': return String(value).trim()
    case 'length': return Array.isArray(value) ? value.length : String(value).length
    case 'join': return Array.isArray(value) ? value.join(arg ?? ', ') : String(value)
    case 'truncate': {
      const n = parseInt(arg ?? '50', 10)
      const s = String(value)
      return s.length > n ? s.slice(0, n) + '...' : s
    }
    case 'default': return value ?? arg ?? ''
    case 'urlencode': return encodeURIComponent(String(value))
    case 'json': return JSON.stringify(value)
    case 'keys': return value && typeof value === 'object' ? Object.keys(value) : []
    case 'values': return value && typeof value === 'object' ? Object.values(value) : []
    default: return value
  }
}

/** Render all template expressions in an object tree */
export function renderObject(obj: unknown, ctx: TemplateContext): unknown {
  if (typeof obj === 'string') {
    // If the entire string is a single expression, return the raw value (not stringified)
    const fullMatch = obj.match(/^\{\{\s*(.+?)\s*\}\}$/)
    if (fullMatch) {
      return evaluateExpression(fullMatch[1].trim(), ctx)
    }
    return renderTemplate(obj, ctx)
  }

  if (Array.isArray(obj)) {
    return obj.map(item => renderObject(item, ctx))
  }

  if (obj && typeof obj === 'object') {
    const result: Record<string, unknown> = {}
    for (const [key, value] of Object.entries(obj)) {
      result[key] = renderObject(value, ctx)
    }
    return result
  }

  return obj
}
