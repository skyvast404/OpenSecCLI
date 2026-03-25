/**
 * Local plugin discovery.
 * Scans ~/.openseccli/plugins/<name>/adapters/ for YAML and TS adapters.
 */

import { existsSync, readdirSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { homedir } from 'node:os'
import YAML from 'js-yaml'
import { getRegistry, registerCommand, parseStrategy } from '../registry.js'
import { log } from '../logger.js'
import { PROVIDER_DOMAIN_MAP } from '../constants/domains.js'
import type { CliCommand, PipelineStep, Arg } from '../types.js'

const PLUGINS_DIR = join(homedir(), '.openseccli', 'plugins')

export async function discoverLocalPlugins(): Promise<number> {
  if (!existsSync(PLUGINS_DIR)) return 0

  let count = 0
  const plugins = readdirSync(PLUGINS_DIR, { withFileTypes: true })
    .filter(d => d.isDirectory())

  for (const plugin of plugins) {
    const pluginDir = join(PLUGINS_DIR, plugin.name)
    const adaptersDir = join(pluginDir, 'adapters')

    if (!existsSync(adaptersDir)) {
      // Maybe plugin has YAML files directly in its root
      const yamlFiles = readdirSync(pluginDir).filter(f => f.endsWith('.yaml') || f.endsWith('.yml'))
      for (const file of yamlFiles) {
        if (registerPluginYaml(join(pluginDir, file), plugin.name)) count++
      }
      continue
    }

    // Scan adapters/<provider>/<name>.yaml structure
    const providers = readdirSync(adaptersDir, { withFileTypes: true })
      .filter(d => d.isDirectory())

    for (const provider of providers) {
      const providerDir = join(adaptersDir, provider.name)
      const files = readdirSync(providerDir)

      for (const file of files) {
        const filePath = join(providerDir, file)
        if (file.endsWith('.yaml') || file.endsWith('.yml')) {
          if (registerPluginYaml(filePath, provider.name)) count++
        } else if (file.endsWith('.js') && !file.endsWith('.d.js') && !file.endsWith('.test.js')) {
          try {
            await import(filePath)
            count++
          } catch (err) {
            log.debug(`Failed to load plugin TS adapter ${filePath}: ${(err as Error).message}`)
          }
        }
      }
    }
  }

  if (count > 0) {
    log.verbose(`Loaded ${count} adapters from local plugins`)
  }
  return count
}

function registerPluginYaml(filePath: string, providerFallback: string): boolean {
  try {
    const content = readFileSync(filePath, 'utf-8')
    const def = YAML.load(content) as Record<string, unknown>
    if (!def || typeof def !== 'object' || !def.name) return false

    const provider = (def.provider as string) ?? providerFallback
    const key = `${provider}/${def.name}`

    // Don't override built-in adapters
    if (getRegistry().has(key)) {
      log.debug(`Plugin adapter ${key} skipped — built-in already registered`)
      return false
    }

    const command: CliCommand = {
      provider,
      name: def.name as string,
      description: (def.description as string) ?? '',
      strategy: parseStrategy((def.strategy as string) ?? 'FREE'),
      auth: def.auth as string | undefined,
      pipeline: def.pipeline as PipelineStep[],
      args: (def.args as Record<string, Arg>) ?? {},
      columns: (def.columns as string[]) ?? [],
      timeout: def.timeout as number | undefined,
      source: 'plugin',
      domain: (def.domain as string) ?? PROVIDER_DOMAIN_MAP[provider],
    }

    registerCommand(command)
    return true
  } catch (error) {
    log.debug(`Failed to load plugin YAML ${filePath}: ${(error as Error).message}`)
    return false
  }
}
