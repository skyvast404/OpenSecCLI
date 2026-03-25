/**
 * Shared utility for running external CLI tools.
 * Handles: tool existence check, spawn, timeout, output parsing, error handling.
 */

import { execFile } from 'node:child_process'
import { promisify } from 'node:util'

const execFileAsync = promisify(execFile)

export interface ToolRunResult {
  stdout: string
  stderr: string
  exitCode: number
}

export interface ToolRunOptions {
  tool: string
  args: string[]
  cwd?: string
  timeout?: number
  maxBuffer?: number
  /** If true, non-zero exit code is not treated as error (e.g., gitleaks exits 1 on findings) */
  allowNonZero?: boolean
  /** Environment variables to pass */
  env?: Record<string, string>
}

/**
 * Check if a CLI tool is installed and in PATH.
 */
export async function checkToolInstalled(tool: string): Promise<boolean> {
  try {
    await execFileAsync('which', [tool])
    return true
  } catch {
    return false
  }
}

/**
 * Check multiple tools, return first available.
 */
export async function findAvailableTool(tools: string[]): Promise<string | null> {
  for (const tool of tools) {
    if (await checkToolInstalled(tool)) return tool
  }
  return null
}

/**
 * Run an external CLI tool and return raw stdout/stderr.
 */
export async function runTool(opts: ToolRunOptions): Promise<ToolRunResult> {
  const timeout = (opts.timeout ?? 120) * 1000
  const maxBuffer = opts.maxBuffer ?? 50 * 1024 * 1024

  try {
    const { stdout, stderr } = await execFileAsync(opts.tool, opts.args, {
      cwd: opts.cwd,
      timeout,
      maxBuffer,
      env: opts.env ? { ...process.env, ...opts.env } : undefined,
    })
    return { stdout: stdout ?? '', stderr: stderr ?? '', exitCode: 0 }
  } catch (error) {
    const err = error as { stdout?: string; stderr?: string; code?: number; message: string }
    if (opts.allowNonZero && err.stdout) {
      return {
        stdout: err.stdout ?? '',
        stderr: err.stderr ?? '',
        exitCode: err.code ?? 1,
      }
    }
    throw error
  }
}

/**
 * Run tool and parse stdout as JSON.
 */
export async function runToolJson<T = unknown>(opts: ToolRunOptions): Promise<T> {
  const result = await runTool(opts)
  return JSON.parse(result.stdout) as T
}

/**
 * Run tool and parse stdout as newline-delimited JSON (JSONL).
 */
export async function runToolJsonLines(opts: ToolRunOptions): Promise<Record<string, unknown>[]> {
  const result = await runTool(opts)
  return parseJsonLines(result.stdout)
}

/**
 * Parse newline-delimited JSON (JSONL) output.
 */
export function parseJsonLines(input: string): Record<string, unknown>[] {
  return input
    .split('\n')
    .filter((line) => line.trim().startsWith('{'))
    .map((line) => {
      try {
        return JSON.parse(line) as Record<string, unknown>
      } catch {
        return null
      }
    })
    .filter((item): item is Record<string, unknown> => item !== null)
}

/**
 * Parse plain text output into rows (one item per line).
 */
export function parseTextLines(input: string): string[] {
  return input
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line.length > 0)
}

/**
 * High-level: run an external tool as an OpenSecCLI adapter.
 * Checks tool availability, runs it, parses output.
 */
export async function runExternalTool(opts: {
  tools: string[]
  buildArgs: (tool: string) => string[]
  cwd?: string
  timeout?: number
  parseOutput: (stdout: string, tool: string) => Record<string, unknown>[]
  allowNonZero?: boolean
  env?: Record<string, string>
}): Promise<{ tool: string; results: Record<string, unknown>[] }> {
  const tool = await findAvailableTool(opts.tools)
  if (!tool) {
    throw new Error(
      `None of these tools are installed: ${opts.tools.join(', ')}. ` +
        `Install one of them to use this command.`,
    )
  }

  const result = await runTool({
    tool,
    args: opts.buildArgs(tool),
    cwd: opts.cwd,
    timeout: opts.timeout,
    allowNonZero: opts.allowNonZero,
    env: opts.env,
  })

  const results = opts.parseOutput(result.stdout, tool)
  return { tool, results }
}
