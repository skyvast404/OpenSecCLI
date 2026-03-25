/**
 * Build-time manifest compiler for OpenSecCLI.
 * Mirrors OpenCLI's build-manifest.ts — compile YAML/TS adapters into cli-manifest.json.
 */

import { readFileSync, writeFileSync, readdirSync, existsSync } from 'fs'
import { join, dirname, relative } from 'path'
import { fileURLToPath } from 'url'
import YAML from 'js-yaml'
import type { ManifestEntry, Arg, PipelineStep } from './types.js'

const __dirname = dirname(fileURLToPath(import.meta.url))
const ADAPTERS_DIR = join(__dirname, 'adapters')
const MANIFEST_PATH = join(__dirname, 'cli-manifest.json')

function scanYaml(providerDir: string, provider: string): ManifestEntry[] {
  const entries: ManifestEntry[] = []
  const files = readdirSync(providerDir).filter(f => f.endsWith('.yaml') || f.endsWith('.yml'))

  for (const file of files) {
    try {
      const content = readFileSync(join(providerDir, file), 'utf-8')
      const def = YAML.load(content) as Record<string, unknown>
      if (!def?.name) continue

      entries.push({
        provider: (def.provider as string) ?? provider,
        name: def.name as string,
        description: (def.description as string) ?? '',
        strategy: (def.strategy as string) ?? 'FREE',
        auth: def.auth as string | undefined,
        args: (def.args as Record<string, Arg>) ?? {},
        columns: (def.columns as string[]) ?? [],
        timeout: def.timeout as number | undefined,
        source: 'yaml',
        pipeline: def.pipeline as PipelineStep[],
      })
    } catch (error) {
      console.error(`Warning: Failed to parse ${file}: ${(error as Error).message}`)
    }
  }

  return entries
}

function scanTs(providerDir: string, provider: string): ManifestEntry[] {
  const entries: ManifestEntry[] = []
  const files = readdirSync(providerDir)
    .filter(f => (f.endsWith('.ts') || f.endsWith('.js')) && !f.endsWith('.test.ts') && !f.endsWith('.d.ts') && !f.endsWith('.js.map'))

  for (const file of files) {
    try {
      const content = readFileSync(join(providerDir, file), 'utf-8')

      // Extract metadata from cli() call — grab the first ~500 chars after cli({
      const cliStart = content.search(/cli\s*\(\s*\{/)
      if (cliStart === -1) continue
      const cliSection = content.slice(cliStart, cliStart + 500)
      const nameMatch = cliSection.match(/name:\s*['"](.+?)['"]/)
      const descMatch = cliSection.match(/description:\s*['"](.+?)['"]/)
      const strategyMatch = cliSection.match(/strategy:\s*Strategy\.(\w+)/)

      if (!nameMatch) continue

      const jsFile = file.endsWith('.js') ? file : file.replace('.ts', '.js')
      const modulePath = relative(__dirname, join(providerDir, jsFile))

      entries.push({
        provider,
        name: nameMatch[1],
        description: descMatch?.[1] ?? '',
        strategy: strategyMatch?.[1] ?? 'FREE',
        args: {},  // TS args are registered at runtime
        columns: [],
        source: 'typescript',
        modulePath,
      })
    } catch (error) {
      console.error(`Warning: Failed to scan ${file}: ${(error as Error).message}`)
    }
  }

  return entries
}

function buildManifest(): void {
  if (!existsSync(ADAPTERS_DIR)) {
    console.log('No adapters directory found, creating empty manifest.')
    writeFileSync(MANIFEST_PATH, '[]')
    return
  }

  const entries: ManifestEntry[] = []
  const seenKeys = new Set<string>()
  const providers = readdirSync(ADAPTERS_DIR, { withFileTypes: true })
    .filter(d => d.isDirectory())

  for (const provider of providers) {
    const providerDir = join(ADAPTERS_DIR, provider.name)

    // TS entries take precedence over YAML (same as OpenCLI)
    const tsEntries = scanTs(providerDir, provider.name)
    const yamlEntries = scanYaml(providerDir, provider.name)

    for (const entry of tsEntries) {
      const key = `${entry.provider}/${entry.name}`
      seenKeys.add(key)
      entries.push(entry)
    }

    for (const entry of yamlEntries) {
      const key = `${entry.provider}/${entry.name}`
      if (!seenKeys.has(key)) {
        entries.push(entry)
      }
    }
  }

  writeFileSync(MANIFEST_PATH, JSON.stringify(entries, null, 2))
  console.log(`Built manifest: ${entries.length} adapters`)
}

buildManifest()
