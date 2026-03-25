/**
 * Traverse a nested object/array by dot-separated path segments.
 * Handles numeric segments as array indices.
 */
export function walkPath(value: unknown, segments: string[]): unknown {
  let current = value
  for (const seg of segments) {
    if (current == null || typeof current !== 'object') return undefined
    if (Array.isArray(current)) {
      const idx = Number(seg)
      current = Number.isNaN(idx) ? undefined : current[idx]
    } else {
      current = (current as Record<string, unknown>)[seg]
    }
  }
  return current
}
