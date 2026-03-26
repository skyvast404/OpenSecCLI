import { describe, it, expect } from 'vitest'
import { readFileSync, existsSync, readdirSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const __dirname = dirname(fileURLToPath(import.meta.url))
const ROOT = join(__dirname, '..', '..')

describe('cli-manifest', () => {
  it('manifest has no duplicate keys', () => {
    const manifestPath = join(ROOT, 'dist', 'cli-manifest.json')
    if (!existsSync(manifestPath)) return // skip if no build

    const manifest = JSON.parse(readFileSync(manifestPath, 'utf-8')) as Array<{
      provider: string
      name: string
      source: string
      modulePath?: string
    }>

    expect(manifest.length).toBeGreaterThanOrEqual(40)

    const keys = manifest.map(e => `${e.provider}/${e.name}`)
    const uniqueKeys = new Set(keys)
    expect(uniqueKeys.size).toBe(keys.length)
  })

  it('no provider starts with underscore', () => {
    const manifestPath = join(ROOT, 'dist', 'cli-manifest.json')
    if (!existsSync(manifestPath)) return

    const manifest = JSON.parse(readFileSync(manifestPath, 'utf-8')) as Array<{ provider: string }>
    for (const entry of manifest) {
      expect(entry.provider).not.toMatch(/^_/)
    }
  })

  it('every TS adapter has a modulePath', () => {
    const manifestPath = join(ROOT, 'dist', 'cli-manifest.json')
    if (!existsSync(manifestPath)) return

    const manifest = JSON.parse(readFileSync(manifestPath, 'utf-8')) as Array<{
      source: string
      modulePath?: string
    }>
    for (const entry of manifest) {
      if (entry.source === 'typescript') {
        expect(entry.modulePath).toBeTruthy()
      }
    }
  })

  it('known providers exist in manifest', () => {
    const manifestPath = join(ROOT, 'dist', 'cli-manifest.json')
    if (!existsSync(manifestPath)) return

    const manifest = JSON.parse(readFileSync(manifestPath, 'utf-8')) as Array<{ provider: string }>
    const providers = new Set(manifest.map(e => e.provider))
    expect(providers.has('scan')).toBe(true)
    expect(providers.has('recon')).toBe(true)
    expect(providers.has('vuln')).toBe(true)
    expect(providers.has('enrichment')).toBe(true)
    expect(providers.has('cloud')).toBe(true)
    expect(providers.has('forensics')).toBe(true)
  })

  it('every adapter .ts file has a cli() registration', () => {
    const adaptersDir = join(ROOT, 'src', 'adapters')
    const providers = readdirSync(adaptersDir, { withFileTypes: true })
      .filter(d => d.isDirectory() && d.name !== '_utils')

    for (const provider of providers) {
      const dir = join(adaptersDir, provider.name)
      const files = readdirSync(dir)
        .filter(f => f.endsWith('.ts') && !f.endsWith('.test.ts') && !f.endsWith('.d.ts'))
        .filter(f => !['types.ts', 'parsers.ts', 'payloads.ts', 'csp-parser.ts', 'cookie-analyzer.ts'].includes(f))

      for (const file of files) {
        const content = readFileSync(join(dir, file), 'utf-8')
        expect(content).toContain('cli(')
      }
    }
  })
})
