import { describe, it, expect } from 'vitest'
import { SKIP_DIRS, walkDir } from '../../src/utils/fs-walk.js'
import { join } from 'node:path'
import { mkdirSync, writeFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'

describe('fs-walk', () => {
  it('SKIP_DIRS contains expected entries', () => {
    expect(SKIP_DIRS.has('node_modules')).toBe(true)
    expect(SKIP_DIRS.has('.git')).toBe(true)
    expect(SKIP_DIRS.has('dist')).toBe(true)
    expect(SKIP_DIRS.has('vendor')).toBe(true)
    expect(SKIP_DIRS.has('target')).toBe(true)
  })

  it('walkDir finds files matching extensions', async () => {
    const root = join(tmpdir(), `fs-walk-test-${Date.now()}`)
    mkdirSync(join(root, 'sub'), { recursive: true })
    writeFileSync(join(root, 'a.ts'), '')
    writeFileSync(join(root, 'b.js'), '')
    writeFileSync(join(root, 'c.txt'), '')
    writeFileSync(join(root, 'sub', 'd.ts'), '')

    try {
      const files = await walkDir(root, { extensions: new Set(['.ts']) })
      expect(files).toHaveLength(2)
      expect(files.every(f => f.endsWith('.ts'))).toBe(true)
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  })

  it('walkDir skips directories in SKIP_DIRS', async () => {
    const root = join(tmpdir(), `fs-walk-skip-${Date.now()}`)
    mkdirSync(join(root, 'node_modules'), { recursive: true })
    mkdirSync(join(root, 'src'), { recursive: true })
    writeFileSync(join(root, 'node_modules', 'pkg.ts'), '')
    writeFileSync(join(root, 'src', 'main.ts'), '')

    try {
      const files = await walkDir(root, { extensions: new Set(['.ts']) })
      expect(files).toHaveLength(1)
      expect(files[0]).toContain('main.ts')
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  })

  it('walkDir respects maxDepth', async () => {
    const root = join(tmpdir(), `fs-walk-depth-${Date.now()}`)
    mkdirSync(join(root, 'a', 'b'), { recursive: true })
    writeFileSync(join(root, 'top.ts'), '')
    writeFileSync(join(root, 'a', 'mid.ts'), '')
    writeFileSync(join(root, 'a', 'b', 'deep.ts'), '')

    try {
      const files = await walkDir(root, { extensions: new Set(['.ts']), maxDepth: 1 })
      expect(files).toHaveLength(2)
      expect(files.some(f => f.endsWith('top.ts'))).toBe(true)
      expect(files.some(f => f.endsWith('mid.ts'))).toBe(true)
      expect(files.some(f => f.endsWith('deep.ts'))).toBe(false)
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  })

  it('walkDir returns empty for non-existent directory', async () => {
    const files = await walkDir('/tmp/does-not-exist-xyz-123', { extensions: new Set(['.ts']) })
    expect(files).toEqual([])
  })

  it('walkDir supports custom skipDirs', async () => {
    const root = join(tmpdir(), `fs-walk-custom-${Date.now()}`)
    mkdirSync(join(root, 'keep'), { recursive: true })
    mkdirSync(join(root, 'skip_me'), { recursive: true })
    writeFileSync(join(root, 'keep', 'a.ts'), '')
    writeFileSync(join(root, 'skip_me', 'b.ts'), '')

    try {
      const files = await walkDir(root, {
        extensions: new Set(['.ts']),
        skipDirs: new Set(['skip_me']),
      })
      expect(files).toHaveLength(1)
      expect(files[0]).toContain('a.ts')
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  })
})
