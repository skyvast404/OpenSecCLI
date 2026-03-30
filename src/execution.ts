/**
 * Command execution engine for OpenSecCLI.
 * Mirrors OpenCLI's execution.ts — unified lifecycle: validate → auth → execute → render.
 */

import { getRegistry } from './registry.js'
import { Strategy } from './types.js'
import type { CliCommand, ExecContext, RenderOptions } from './types.js'
import { render } from './output.js'
import { log } from './logger.js'
import { loadAuth } from './auth/index.js'
import { executePipeline } from './pipeline/executor.js'
import { runWithTimeout, getCommandTimeout } from './runtime.js'
import { fireHook } from './hooks.js'
import {
  CommandNotFoundError,
  AuthRequiredError,
  ArgumentError,
  EmptyResultError,
} from './errors.js'
import { upsertFinding, recordScan, fingerprint as buildFingerprint } from './db/store.js'

export async function executeCommand(
  commandId: string,
  rawArgs: Record<string, unknown>,
  options: { format?: string },
): Promise<void> {
  const registry = getRegistry()
  const command = registry.get(commandId)
  if (!command) throw new CommandNotFoundError(commandId)

  // 1. Validate and coerce arguments
  const args = coerceAndValidateArgs(command, rawArgs)

  // 2. Fire onBeforeExecute hook
  await fireHook('onBeforeExecute', { command: commandId, args })

  // 3. Resolve authentication
  const authProvider = command.auth ?? command.provider
  let auth = null
  if (command.strategy !== Strategy.FREE) {
    auth = loadAuth(authProvider)
    if (!auth) throw new AuthRequiredError(authProvider)
  }

  // 4. Execute (func or pipeline)
  const startedAt = Date.now()
  const timeout = command.timeout ?? getCommandTimeout()
  let result: unknown

  const ctx: ExecContext = { auth, args, log }

  try {
    if (command.func) {
      result = await runWithTimeout(command.func(ctx, args), timeout)
    } else if (command.pipeline) {
      result = await runWithTimeout(
        executePipeline(command.pipeline, { args, auth }),
        timeout,
      )
    } else {
      throw new Error(`Command ${commandId} has no func or pipeline`)
    }
  } catch (error) {
    await fireHook('onAfterExecute', {
      command: commandId,
      args,
      startedAt,
      error,
    })
    throw error
  }

  // 5. Handle empty results — return empty array, not error
  //    "No findings" is a success (exit 0), not an error
  if (result === null || result === undefined) {
    result = []
  }

  const elapsed = Date.now() - startedAt

  // 5b. Auto-save findings to DB (best-effort, don't fail the command)
  try {
    const target = extractTarget(args, commandId)
    if (target && Array.isArray(result) && result.length > 0) {
      const seenFps: string[] = []
      for (const item of result as Record<string, unknown>[]) {
        const finding = {
          source: commandId,
          severity: String(item.severity ?? item.risk ?? item.level ?? 'info').toLowerCase(),
          title: String(item.title ?? item.rule_id ?? item.header ?? item.check ?? item.finding ?? item.name ?? 'Finding'),
          detail: String(item.detail ?? item.message ?? item.description ?? item.value ?? ''),
          file_path: (item.file_path as string | undefined) ?? (item.file as string | undefined) ?? undefined,
          line: (item.start_line as number | undefined) ?? (item.line as number | undefined) ?? undefined,
          cwe: (item.cwe as string | undefined) ?? undefined,
          raw: item,
        }
        upsertFinding(target, finding)
        seenFps.push(buildFingerprint(finding))
      }
      recordScan(target, commandId, result.length, elapsed)
    }
  } catch {
    // DB save is best-effort — don't break the command
  }

  // 6. Render output
  const renderOpts: RenderOptions = {
    format: (options.format ?? 'table') as RenderOptions['format'],
    columns: command.columns,
    source: command.provider,
    elapsed,
  }
  render(result, renderOpts)

  // 7. Fire onAfterExecute hook
  await fireHook('onAfterExecute', {
    command: commandId,
    args,
    startedAt,
    finishedAt: Date.now(),
  })
}

function extractTarget(args: Record<string, unknown>, _commandId: string): string | null {
  for (const key of ['target', 'url', 'domain', 'ip', 'host', 'path', 'file', 'image', 'hash']) {
    if (args[key] && typeof args[key] === 'string') {
      return args[key] as string
    }
  }
  return null
}

function coerceAndValidateArgs(
  command: CliCommand,
  rawArgs: Record<string, unknown>,
): Record<string, unknown> {
  const result: Record<string, unknown> = {}

  for (const [name, def] of Object.entries(command.args)) {
    let value = rawArgs[name]

    // Apply default
    if (value === undefined && def.default !== undefined) {
      value = def.default
    }

    // Check required
    if (def.required && (value === undefined || value === null || value === '')) {
      throw new ArgumentError(`Missing required argument: --${name}`)
    }

    if (value === undefined) continue

    // Type coercion
    switch (def.type) {
      case 'number': {
        const num = Number(value)
        if (isNaN(num)) {
          throw new ArgumentError(`--${name} must be a number, got: ${value}`)
        }
        value = num
        break
      }
      case 'boolean': {
        if (typeof value === 'string') {
          value = value === 'true' || value === '1'
        }
        value = Boolean(value)
        break
      }
      case 'string': {
        value = String(value)
        break
      }
    }

    // Choices validation
    if (def.choices && !def.choices.includes(String(value))) {
      throw new ArgumentError(
        `--${name} must be one of: ${def.choices.join(', ')} (got: ${value})`,
      )
    }

    result[name] = value
  }

  return result
}
