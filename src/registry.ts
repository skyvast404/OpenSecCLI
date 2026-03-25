/**
 * Command registry for OpenSecCLI.
 * Mirrors OpenCLI's registry.ts — globalThis singleton, cli() registration function.
 */

import { Strategy } from './types.js'
import type { CliCommand, CliOptions, Arg } from './types.js'

const REGISTRY_KEY = '__openseccli_registry__'

export function getRegistry(): Map<string, CliCommand> {
  if (!(globalThis as any)[REGISTRY_KEY]) {
    (globalThis as any)[REGISTRY_KEY] = new Map<string, CliCommand>()
  }
  return (globalThis as any)[REGISTRY_KEY]
}

export function cli(options: CliOptions): CliCommand {
  const command: CliCommand = {
    provider: options.provider,
    name: options.name,
    description: options.description ?? '',
    strategy: options.strategy ?? Strategy.FREE,
    auth: options.auth,
    domain: options.domain,
    func: options.func,
    pipeline: options.pipeline,
    args: options.args ?? {},
    columns: options.columns ?? [],
    timeout: options.timeout,
  }

  getRegistry().set(fullName(command), command)
  return command
}

export function fullName(cmd: Pick<CliCommand, 'provider' | 'name'>): string {
  return `${cmd.provider}/${cmd.name}`
}

export function registerCommand(command: CliCommand): void {
  getRegistry().set(fullName(command), command)
}

export function parseStrategy(value: string): Strategy {
  const normalized = value.toUpperCase()
  if (normalized in Strategy) {
    return Strategy[normalized as keyof typeof Strategy]
  }
  return Strategy.API_KEY
}

export { Strategy }
export type { CliCommand, CliOptions, Arg }
