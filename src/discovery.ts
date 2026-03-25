/**
 * Adapter discovery for OpenSecCLI.
 * Mirrors OpenCLI's discovery.ts — fast manifest path + filesystem fallback.
 */

import { readFileSync, existsSync, readdirSync, statSync } from 'fs'
import { join, dirname } from 'path'
import { fileURLToPath } from 'url'
import YAML from 'js-yaml'
import { getRegistry, registerCommand, parseStrategy } from './registry.js'
import { Strategy } from './types.js'
import { log } from './logger.js'
import type { CliCommand, ManifestEntry, PipelineStep, Arg } from './types.js'

const __dirname = dirname(fileURLToPath(import.meta.url))

export async function discoverAdapters(): Promise<void> {
  // Fast path: pre-compiled manifest
  const manifestPath = join(__dirname, 'cli-manifest.json')
  if (existsSync(manifestPath)) {
    loadFromManifest(manifestPath)
    return
  }

  // Fallback: filesystem scan (development mode)
  await discoverFromFilesystem(join(__dirname, 'adapters'))
}

function loadFromManifest(manifestPath: string): void {
  try {
    const content = readFileSync(manifestPath, 'utf-8')
    const entries: ManifestEntry[] = JSON.parse(content)

    for (const entry of entries) {
      const command: CliCommand = {
        provider: entry.provider,
        name: entry.name,
        description: entry.description,
        strategy: parseStrategy(entry.strategy),
        auth: entry.auth,
        args: entry.args,
        columns: entry.columns,
        timeout: entry.timeout,
        pipeline: entry.pipeline,
        source: entry.source,
      }

      // TypeScript adapters: lazy-load the module on first execution
      if (entry.source === 'typescript' && entry.modulePath) {
        const modulePath = entry.modulePath
        command.func = async (ctx, args) => {
          const mod = await import(join(__dirname, modulePath))
          const loadedCmd = getRegistry().get(`${entry.provider}/${entry.name}`)
          if (loadedCmd?.func && loadedCmd.func !== command.func) {
            return loadedCmd.func(ctx, args)
          }
          throw new Error(`Module ${modulePath} did not register a func`)
        }
      }

      registerCommand(command)
    }

    log.verbose(`Loaded ${entries.length} adapters from manifest`)
  } catch (error) {
    log.warn(`Failed to load manifest: ${(error as Error).message}`)
  }
}

async function discoverFromFilesystem(adaptersDir: string): Promise<void> {
  if (!existsSync(adaptersDir)) {
    log.debug(`Adapters directory not found: ${adaptersDir}`)
    return
  }

  const providers = readdirSync(adaptersDir, { withFileTypes: true })
    .filter(d => d.isDirectory())

  for (const provider of providers) {
    const providerDir = join(adaptersDir, provider.name)
    const files = readdirSync(providerDir)

    for (const file of files) {
      const filePath = join(providerDir, file)

      if (file.endsWith('.yaml') || file.endsWith('.yml')) {
        registerYamlAdapter(filePath, provider.name)
      } else if (file.endsWith('.ts') && !file.endsWith('.test.ts') && !file.endsWith('.d.ts')) {
        try {
          await import(filePath)
        } catch (error) {
          log.debug(`Failed to load TS adapter ${filePath}: ${(error as Error).message}`)
        }
      }
    }
  }

  log.verbose(`Discovered ${getRegistry().size} adapters from filesystem`)
}

function registerYamlAdapter(filePath: string, providerFallback: string): void {
  try {
    const content = readFileSync(filePath, 'utf-8')
    const def = YAML.load(content) as Record<string, unknown>

    if (!def || typeof def !== 'object') return

    const command: CliCommand = {
      provider: (def.provider as string) ?? providerFallback,
      name: def.name as string,
      description: (def.description as string) ?? '',
      strategy: parseStrategy((def.strategy as string) ?? 'FREE'),
      auth: def.auth as string | undefined,
      pipeline: def.pipeline as PipelineStep[],
      args: (def.args as Record<string, Arg>) ?? {},
      columns: (def.columns as string[]) ?? [],
      timeout: def.timeout as number | undefined,
      source: 'yaml',
    }

    registerCommand(command)
  } catch (error) {
    log.debug(`Failed to load YAML adapter ${filePath}: ${(error as Error).message}`)
  }
}
