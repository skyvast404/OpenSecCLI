/**
 * Shared filesystem walk utility.
 * Replaces duplicated walkDir/walkSourceFiles in scan adapters.
 */

import { readdir } from 'node:fs/promises'
import { join, extname } from 'node:path'

export const SKIP_DIRS = new Set([
  'node_modules', '.git', '__pycache__', '.venv', 'venv',
  'dist', 'build', '.next', 'vendor', 'target',
])

export interface WalkOptions {
  extensions: Set<string>
  maxDepth?: number
  skipDirs?: Set<string>
}

export async function walkDir(
  dir: string,
  opts: WalkOptions,
  depth = 0,
): Promise<string[]> {
  const maxDepth = opts.maxDepth ?? 10
  const skipDirs = opts.skipDirs ?? SKIP_DIRS

  if (depth > maxDepth) return []

  const results: string[] = []
  try {
    const entries = await readdir(dir, { withFileTypes: true })
    for (const entry of entries) {
      if (entry.name.startsWith('.') && entry.name !== '.') continue
      const fullPath = join(dir, entry.name)

      if (entry.isDirectory()) {
        if (skipDirs.has(entry.name)) continue
        const sub = await walkDir(fullPath, opts, depth + 1)
        results.push(...sub)
      } else if (entry.isFile()) {
        if (opts.extensions.has(extname(entry.name).toLowerCase())) {
          results.push(fullPath)
        }
      }
    }
  } catch {
    // Directory not readable — skip silently
  }
  return results
}
