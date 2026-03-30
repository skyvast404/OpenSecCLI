/**
 * Continuous security monitoring.
 * opensec watch start --workflow web-audit.yaml --target example.com --interval 1h
 * opensec watch list
 * opensec watch run <id>
 * opensec watch stop <id>
 * opensec watch history <id>
 */

import type { Command } from 'commander'
import chalk from 'chalk'
import { randomBytes } from 'node:crypto'
import { mkdirSync, existsSync, readFileSync, writeFileSync, readdirSync, unlinkSync } from 'node:fs'
import { join } from 'node:path'
import { homedir } from 'node:os'
import { render } from '../output.js'
import { log } from '../logger.js'
import { CONFIG_DIR_NAME, EXIT_CODES } from '../constants.js'
import { runWorkflow } from './workflow.js'
import { getRegistry } from '../registry.js'
import { getDiff } from '../db/store.js'

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface WatchConfig {
  readonly id: string
  readonly target: string
  readonly workflow?: string
  readonly command?: string
  readonly interval: string
  readonly alertWebhook?: string
  readonly createdAt: string
  readonly lastRunAt?: string
  readonly lastFindingsCount?: number
  readonly runCount: number
}

export interface WatchRunRecord {
  readonly watchId: string
  readonly ranAt: string
  readonly findingsCount: number
  readonly newFindings: number
  readonly resolvedFindings: number
  readonly durationMs: number
  readonly status: 'completed' | 'failed'
  readonly error?: string
}

export interface AlertPayload {
  readonly source: string
  readonly watch_id: string
  readonly target: string
  readonly timestamp: string
  readonly new_findings: number
  readonly resolved_findings: number
  readonly total_findings: number
  readonly critical: number
  readonly high: number
  readonly summary: string
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const WATCHES_DIR_NAME = 'watches'
const WATCH_HISTORY_DIR_NAME = 'watch-history'

// ---------------------------------------------------------------------------
// Directory helpers (overridable for tests)
// ---------------------------------------------------------------------------

let baseDirOverride: string | null = null

export function setWatchBaseDir(dir: string | null): void {
  baseDirOverride = dir
}

function getBaseDir(): string {
  return baseDirOverride ?? join(homedir(), CONFIG_DIR_NAME)
}

function getWatchesDir(): string {
  const dir = join(getBaseDir(), WATCHES_DIR_NAME)
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true })
  }
  return dir
}

function getHistoryDir(): string {
  const dir = join(getBaseDir(), WATCH_HISTORY_DIR_NAME)
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true })
  }
  return dir
}

// ---------------------------------------------------------------------------
// Interval parsing
// ---------------------------------------------------------------------------

/** Parse a human-readable interval string to milliseconds. */
export function parseInterval(interval: string): number {
  const match = interval.match(/^(\d+)(m|h|d)$/)
  if (!match) {
    throw new Error(`Invalid interval format: "${interval}". Use e.g. "30m", "1h", "24h", "7d".`)
  }
  const value = parseInt(match[1], 10)
  const unit = match[2]

  const multipliers: Record<string, number> = {
    m: 60 * 1000,
    h: 60 * 60 * 1000,
    d: 24 * 60 * 60 * 1000,
  }

  return value * multipliers[unit]
}

// ---------------------------------------------------------------------------
// Watch config CRUD
// ---------------------------------------------------------------------------

function generateId(): string {
  return randomBytes(4).toString('hex')
}

function watchConfigPath(id: string): string {
  return join(getWatchesDir(), `${id}.json`)
}

export function saveWatchConfig(config: WatchConfig): void {
  writeFileSync(watchConfigPath(config.id), JSON.stringify(config, null, 2), 'utf-8')
}

export function loadWatchConfig(id: string): WatchConfig | null {
  const filePath = watchConfigPath(id)
  if (!existsSync(filePath)) {
    return null
  }
  const raw = readFileSync(filePath, 'utf-8')
  return JSON.parse(raw) as WatchConfig
}

export function listWatchConfigs(): WatchConfig[] {
  const dir = getWatchesDir()
  const files = readdirSync(dir).filter(f => f.endsWith('.json'))
  return files.map(f => {
    const raw = readFileSync(join(dir, f), 'utf-8')
    return JSON.parse(raw) as WatchConfig
  })
}

export function deleteWatchConfig(id: string): boolean {
  const filePath = watchConfigPath(id)
  if (!existsSync(filePath)) {
    return false
  }
  unlinkSync(filePath)
  return true
}

// ---------------------------------------------------------------------------
// Watch history
// ---------------------------------------------------------------------------

function historyFilePath(watchId: string): string {
  return join(getHistoryDir(), `${watchId}.json`)
}

function loadHistory(watchId: string): WatchRunRecord[] {
  const filePath = historyFilePath(watchId)
  if (!existsSync(filePath)) {
    return []
  }
  const raw = readFileSync(filePath, 'utf-8')
  return JSON.parse(raw) as WatchRunRecord[]
}

function appendHistory(record: WatchRunRecord): void {
  const existing = loadHistory(record.watchId)
  const updated = [...existing, record]
  writeFileSync(historyFilePath(record.watchId), JSON.stringify(updated, null, 2), 'utf-8')
}

// ---------------------------------------------------------------------------
// Alert payload
// ---------------------------------------------------------------------------

/** Build a webhook alert payload from run results. */
export function buildAlertPayload(opts: {
  readonly watchId: string
  readonly target: string
  readonly newFindings: number
  readonly resolvedFindings: number
  readonly totalFindings: number
  readonly critical: number
  readonly high: number
}): AlertPayload {
  const parts: string[] = []
  if (opts.newFindings > 0) {
    parts.push(`${opts.newFindings} new finding${opts.newFindings === 1 ? '' : 's'} detected`)
  }
  if (opts.critical > 0) {
    parts.push(`${opts.critical} critical`)
  }
  if (opts.resolvedFindings > 0) {
    parts.push(`${opts.resolvedFindings} resolved`)
  }
  const summary = parts.length > 0 ? parts.join(', ') : 'No changes'

  return {
    source: 'openseccli',
    watch_id: opts.watchId,
    target: opts.target,
    timestamp: new Date().toISOString(),
    new_findings: opts.newFindings,
    resolved_findings: opts.resolvedFindings,
    total_findings: opts.totalFindings,
    critical: opts.critical,
    high: opts.high,
    summary,
  }
}

// ---------------------------------------------------------------------------
// Send alert
// ---------------------------------------------------------------------------

async function sendAlert(webhookUrl: string, payload: AlertPayload): Promise<void> {
  try {
    const response = await fetch(webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    })
    if (!response.ok) {
      log.warn(`Alert webhook returned ${response.status}: ${response.statusText}`)
    } else {
      log.info(`Alert sent to webhook (${payload.new_findings} new findings)`)
    }
  } catch (err) {
    log.error(`Failed to send alert: ${(err as Error).message}`)
  }
}

// ---------------------------------------------------------------------------
// Watch run logic
// ---------------------------------------------------------------------------

async function executeWatchRun(config: WatchConfig): Promise<WatchRunRecord> {
  const startTime = Date.now()
  const sinceDate = config.lastRunAt ?? config.createdAt

  try {
    let findingsCount = 0

    if (config.workflow) {
      const results = await runWorkflow(config.workflow, { target: config.target })
      findingsCount = results.reduce((sum, r) => sum + r.findings, 0)
    } else if (config.command) {
      const registry = getRegistry()
      const cmd = registry.get(config.command)
      if (!cmd) {
        throw new Error(`Command not found in registry: ${config.command}`)
      }
      const ctx = { auth: null, args: { target: config.target }, log }
      const result = cmd.func ? await cmd.func(ctx, { target: config.target }) : []
      findingsCount = Array.isArray(result) ? result.length : 1
    } else {
      throw new Error('Watch config must specify either workflow or command')
    }

    // Diff detection via Finding DB
    const diff = getDiff(config.target, sinceDate)
    const durationMs = Date.now() - startTime

    const record: WatchRunRecord = {
      watchId: config.id,
      ranAt: new Date().toISOString(),
      findingsCount,
      newFindings: diff.new_findings.length,
      resolvedFindings: diff.resolved.length,
      durationMs,
      status: 'completed',
    }

    // Send alert if configured and new findings exist
    if (config.alertWebhook && diff.new_findings.length > 0) {
      const criticalCount = diff.new_findings.filter(f => f.severity === 'critical').length
      const highCount = diff.new_findings.filter(f => f.severity === 'high').length

      const payload = buildAlertPayload({
        watchId: config.id,
        target: config.target,
        newFindings: diff.new_findings.length,
        resolvedFindings: diff.resolved.length,
        totalFindings: findingsCount,
        critical: criticalCount,
        high: highCount,
      })

      await sendAlert(config.alertWebhook, payload)
    }

    // Update config immutably
    const updatedConfig: WatchConfig = {
      ...config,
      lastRunAt: record.ranAt,
      lastFindingsCount: findingsCount,
      runCount: config.runCount + 1,
    }
    saveWatchConfig(updatedConfig)

    // Append to history
    appendHistory(record)

    return record
  } catch (err) {
    const durationMs = Date.now() - startTime
    const record: WatchRunRecord = {
      watchId: config.id,
      ranAt: new Date().toISOString(),
      findingsCount: 0,
      newFindings: 0,
      resolvedFindings: 0,
      durationMs,
      status: 'failed',
      error: (err as Error).message,
    }

    appendHistory(record)
    return record
  }
}

// ---------------------------------------------------------------------------
// CLI registration
// ---------------------------------------------------------------------------

export function registerWatchCommands(program: Command): void {
  const watchCmd = program
    .command('watch')
    .description('Continuous security monitoring — start, list, run, stop, history')

  // opensec watch start
  watchCmd
    .command('start')
    .description('Start watching a target')
    .requiredOption('--target <target>', 'Target URL or domain to monitor')
    .option('--workflow <yaml>', 'Path to workflow YAML file')
    .option('--command <cmd>', 'Single command to run (e.g., "vuln/header-audit")')
    .option('--interval <duration>', 'Scan interval: "30m", "1h", "6h", "24h"', '1h')
    .option('--alert <webhook-url>', 'Webhook URL for alert notifications')
    .action(async (opts: {
      target: string
      workflow?: string
      command?: string
      interval: string
      alert?: string
    }) => {
      if (!opts.workflow && !opts.command) {
        process.stderr.write(chalk.red('Error: specify --workflow <yaml> or --command <cmd>\n'))
        process.exit(EXIT_CODES.BAD_ARGUMENT)
      }

      // Validate interval
      try {
        parseInterval(opts.interval)
      } catch (err) {
        process.stderr.write(chalk.red(`Error: ${(err as Error).message}\n`))
        process.exit(EXIT_CODES.BAD_ARGUMENT)
      }

      const id = generateId()
      const config: WatchConfig = {
        id,
        target: opts.target,
        workflow: opts.workflow,
        command: opts.command,
        interval: opts.interval,
        alertWebhook: opts.alert,
        createdAt: new Date().toISOString(),
        runCount: 0,
      }

      saveWatchConfig(config)
      process.stderr.write(chalk.green(`\nWatch created: ${id}\n`))
      process.stderr.write(`  Target:   ${config.target}\n`)
      process.stderr.write(`  Source:   ${config.workflow ?? config.command}\n`)
      process.stderr.write(`  Interval: ${config.interval}\n`)
      if (config.alertWebhook) {
        process.stderr.write(`  Alert:    ${config.alertWebhook}\n`)
      }
      process.stderr.write('\n')

      // Run the first scan immediately
      process.stderr.write(chalk.blue('Running initial scan...\n'))
      const record = await executeWatchRun(config)

      if (record.status === 'completed') {
        process.stderr.write(chalk.green(`Initial scan complete: ${record.findingsCount} finding(s)\n`))
      } else {
        process.stderr.write(chalk.red(`Initial scan failed: ${record.error}\n`))
      }

      // Schedule next run using setTimeout (foreground mode)
      const intervalMs = parseInterval(config.interval)
      process.stderr.write(chalk.gray(`\nNext scan in ${config.interval}. Press Ctrl+C to stop.\n`))

      const runLoop = async (): Promise<void> => {
        const currentConfig = loadWatchConfig(id)
        if (!currentConfig) {
          process.stderr.write(chalk.yellow('\nWatch config removed. Stopping.\n'))
          return
        }

        process.stderr.write(chalk.blue(`\n[${new Date().toISOString()}] Running scheduled scan...\n`))
        const result = await executeWatchRun(currentConfig)

        if (result.status === 'completed') {
          process.stderr.write(
            chalk.green(`Scan complete: ${result.findingsCount} finding(s), ${result.newFindings} new\n`),
          )
        } else {
          process.stderr.write(chalk.red(`Scan failed: ${result.error}\n`))
        }

        setTimeout(() => { void runLoop() }, intervalMs)
      }

      setTimeout(() => { void runLoop() }, intervalMs)
    })

  // opensec watch list
  watchCmd
    .command('list')
    .description('List active watches')
    .action(() => {
      const configs = listWatchConfigs()
      if (configs.length === 0) {
        process.stderr.write('No active watches. Start one with: opensec watch start --target <target> --workflow <yaml>\n')
        return
      }

      const globalOpts = program.opts()
      const format = globalOpts.json ? 'json' : (globalOpts.format ?? 'table')

      const rows = configs.map(c => ({
        id: c.id,
        target: c.target,
        source: c.workflow ?? c.command ?? '-',
        interval: c.interval,
        last_run: c.lastRunAt ?? '-',
        findings: c.lastFindingsCount ?? 0,
        runs: c.runCount,
      }))

      render(rows, {
        format: format as 'table' | 'json' | 'csv' | 'yaml' | 'markdown',
        columns: ['id', 'target', 'source', 'interval', 'last_run', 'findings', 'runs'],
      })
    })

  // opensec watch run <id>
  watchCmd
    .command('run <id>')
    .description('Manually trigger a watch run')
    .action(async (id: string) => {
      const config = loadWatchConfig(id)
      if (!config) {
        process.stderr.write(chalk.red(`Watch not found: ${id}\n`))
        process.exit(EXIT_CODES.NOT_FOUND)
      }

      process.stderr.write(chalk.blue(`Running watch ${id} (${config.target})...\n`))
      const record = await executeWatchRun(config)

      if (record.status === 'completed') {
        process.stderr.write(chalk.green(
          `\nCompleted in ${(record.durationMs / 1000).toFixed(1)}s\n` +
          `  Findings:   ${record.findingsCount}\n` +
          `  New:        ${record.newFindings}\n` +
          `  Resolved:   ${record.resolvedFindings}\n`,
        ))
      } else {
        process.stderr.write(chalk.red(`\nFailed: ${record.error}\n`))
        process.exit(EXIT_CODES.RUNTIME_ERROR)
      }
    })

  // opensec watch stop <id>
  watchCmd
    .command('stop <id>')
    .description('Remove a watch')
    .action((id: string) => {
      const removed = deleteWatchConfig(id)
      if (removed) {
        process.stderr.write(chalk.green(`Watch ${id} stopped and removed.\n`))
      } else {
        process.stderr.write(chalk.red(`Watch not found: ${id}\n`))
        process.exit(EXIT_CODES.NOT_FOUND)
      }
    })

  // opensec watch history <id>
  watchCmd
    .command('history <id>')
    .description('Show run history for a watch')
    .action((id: string) => {
      const config = loadWatchConfig(id)
      if (!config) {
        process.stderr.write(chalk.red(`Watch not found: ${id}\n`))
        process.exit(EXIT_CODES.NOT_FOUND)
      }

      const history = loadHistory(id)
      if (history.length === 0) {
        process.stderr.write(`No run history for watch ${id}.\n`)
        return
      }

      const globalOpts = program.opts()
      const format = globalOpts.json ? 'json' : (globalOpts.format ?? 'table')

      const rows = history.map(r => ({
        ran_at: r.ranAt,
        status: r.status,
        findings: r.findingsCount,
        new: r.newFindings,
        resolved: r.resolvedFindings,
        duration: `${(r.durationMs / 1000).toFixed(1)}s`,
        error: r.error ?? '-',
      }))

      render(rows, {
        format: format as 'table' | 'json' | 'csv' | 'yaml' | 'markdown',
        columns: ['ran_at', 'status', 'findings', 'new', 'resolved', 'duration'],
      })
    })
}
