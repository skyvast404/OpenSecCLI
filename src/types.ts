/**
 * Core type definitions for OpenSecCLI.
 * Mirrors OpenCLI's types.ts — adapted for security API scenarios.
 */

export type ArgType = 'string' | 'number' | 'boolean'

export interface Arg {
  type: ArgType
  required?: boolean
  default?: unknown
  choices?: string[]
  help?: string
}

export interface PipelineStep {
  [stepName: string]: Record<string, unknown>
}

export interface CliCommand {
  provider: string
  name: string
  description: string
  strategy: Strategy
  auth?: string
  func?: (ctx: ExecContext, args: Record<string, unknown>) => Promise<unknown>
  pipeline?: PipelineStep[]
  args: Record<string, Arg>
  columns: string[]
  timeout?: number
  source?: 'yaml' | 'typescript' | 'plugin'
}

export interface CliOptions {
  provider: string
  name: string
  description?: string
  strategy?: Strategy
  auth?: string
  func?: (ctx: ExecContext, args: Record<string, unknown>) => Promise<unknown>
  pipeline?: PipelineStep[]
  args?: Record<string, Arg>
  columns?: string[]
  timeout?: number
}

export enum Strategy {
  FREE = 'FREE',
  API_KEY = 'API_KEY',
  OAUTH = 'OAUTH',
  CERT = 'CERT',
}

export interface ExecContext {
  auth: AuthCredentials | null
  args: Record<string, unknown>
  log: Logger
}

export interface AuthCredentials {
  api_key?: string
  token?: string
  username?: string
  password?: string
  [key: string]: unknown
}

export interface Logger {
  info(msg: string): void
  warn(msg: string): void
  error(msg: string): void
  verbose(msg: string): void
  debug(msg: string): void
  step(index: number, total: number, name: string): void
}

export interface RenderOptions {
  format?: 'table' | 'json' | 'csv' | 'yaml' | 'markdown'
  columns?: string[]
  source?: string
  elapsed?: number
  footerExtra?: string
}

export interface ManifestEntry {
  provider: string
  name: string
  description: string
  strategy: string
  auth?: string
  args: Record<string, Arg>
  columns: string[]
  timeout?: number
  source: 'yaml' | 'typescript'
  modulePath?: string
  pipeline?: PipelineStep[]
}

export interface HookContext {
  command: string
  args: Record<string, unknown>
  startedAt?: number
  finishedAt?: number
  error?: unknown
  [key: string]: unknown
}

export type HookFn = (ctx: HookContext) => Promise<void> | void
