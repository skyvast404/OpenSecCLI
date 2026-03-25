/**
 * Lifecycle hooks for OpenSecCLI.
 * Mirrors OpenCLI's hooks.ts — globalThis singleton, plugin-safe.
 */

import type { HookFn, HookContext } from './types.js'

type HookName = 'onStartup' | 'onBeforeExecute' | 'onAfterExecute'

const HOOKS_KEY = '__openseccli_hooks__'

function getHooks(): Record<HookName, HookFn[]> {
  if (!(globalThis as any)[HOOKS_KEY]) {
    (globalThis as any)[HOOKS_KEY] = {
      onStartup: [],
      onBeforeExecute: [],
      onAfterExecute: [],
    }
  }
  return (globalThis as any)[HOOKS_KEY]
}

function registerHook(name: HookName, fn: HookFn): void {
  getHooks()[name].push(fn)
}

export function onStartup(fn: HookFn): void {
  registerHook('onStartup', fn)
}

export function onBeforeExecute(fn: HookFn): void {
  registerHook('onBeforeExecute', fn)
}

export function onAfterExecute(fn: HookFn): void {
  registerHook('onAfterExecute', fn)
}

export async function fireHook(name: HookName, ctx: HookContext): Promise<void> {
  const hooks = getHooks()[name]
  for (const fn of hooks) {
    try {
      await fn(ctx)
    } catch {
      // Failing hooks never block execution (same as OpenCLI)
    }
  }
}
