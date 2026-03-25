/**
 * Public plugin API for OpenSecCLI.
 * Mirrors OpenCLI's registry-api.ts — re-exports for external consumers.
 *
 * Usage: import { cli, Strategy } from 'openseccli/registry'
 */

export { cli, Strategy, getRegistry, fullName, registerCommand } from './registry.js'
export type { CliCommand, CliOptions, Arg } from './registry.js'
export type { ExecContext, AuthCredentials, HookContext, HookFn } from './types.js'
export { onStartup, onBeforeExecute, onAfterExecute } from './hooks.js'
