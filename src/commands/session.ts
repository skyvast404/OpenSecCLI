/**
 * Engagement Session Manager.
 * opensec session start --target example.com --name "Q2-pentest"
 * opensec session stop
 * opensec session status
 * opensec session list
 * opensec session report [--format html|json]
 * opensec session diff --previous <name>
 */

import type { Command } from 'commander'
import chalk from 'chalk'
import { writeFile } from 'node:fs/promises'
import { render } from '../output.js'
import { EXIT_CODES } from '../constants.js'
import {
  createSession,
  loadSession,
  listSessions,
  saveSession,
  sessionExists,
  getActiveSessionName,
  setActiveSessionName,
  clearActiveSession,
} from '../session/store.js'
import type { Session } from '../session/types.js'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function getFormat(program: Command): string {
  const globalOpts = program.opts()
  return globalOpts.json ? 'json' : (globalOpts.format ?? 'table')
}

function formatDuration(ms: number): string {
  if (ms < 1000) return `${ms}ms`
  if (ms < 60_000) return `${(ms / 1000).toFixed(1)}s`
  const mins = Math.floor(ms / 60_000)
  const secs = Math.floor((ms % 60_000) / 1000)
  return `${mins}m ${secs}s`
}

function requireActiveSession(): { name: string; session: Session } {
  const name = getActiveSessionName()
  if (!name) {
    process.stderr.write(chalk.red('No active session. Run: opensec session start --target <target> --name <name>\n'))
    process.exit(EXIT_CODES.RUNTIME_ERROR)
  }

  const session = loadSession(name)
  if (!session) {
    process.stderr.write(chalk.red(`Session file not found for: ${name}\n`))
    process.exit(EXIT_CODES.RUNTIME_ERROR)
  }

  return { name, session }
}

// ---------------------------------------------------------------------------
// Session report — reuses report.ts HTML generator
// ---------------------------------------------------------------------------

function buildSessionReportJson(session: Session): Record<string, unknown> {
  return {
    name: session.name,
    target: session.target,
    status: session.status,
    createdAt: session.createdAt,
    updatedAt: session.updatedAt,
    summary: session.summary,
    steps: session.steps,
  }
}

async function buildSessionReportHtml(session: Session): Promise<string> {
  const { normalizeInput, buildHtml } = await import('./report.js')

  // Build synthetic findings from session steps for the HTML report
  const findings = session.steps.map(step => ({
    severity: 'info' as const,
    source: step.command,
    title: `${step.command} — ${step.findings_count} finding(s)`,
    detail: `Duration: ${formatDuration(step.duration_ms)}, Args: ${JSON.stringify(step.args)}`,
  }))

  const report = normalizeInput(findings, `Session Report: ${session.name}`)
  return buildHtml({
    ...report,
    target: session.target,
    date: session.createdAt,
  })
}

// ---------------------------------------------------------------------------
// Session diff
// ---------------------------------------------------------------------------

interface DiffResult {
  readonly added: readonly string[]
  readonly removed: readonly string[]
  readonly current_commands: number
  readonly previous_commands: number
  readonly current_findings: number
  readonly previous_findings: number
}

function diffSessions(current: Session, previous: Session): DiffResult {
  const currentCommands = new Set(current.steps.map(s => s.command))
  const previousCommands = new Set(previous.steps.map(s => s.command))

  const added = [...currentCommands].filter(c => !previousCommands.has(c))
  const removed = [...previousCommands].filter(c => !currentCommands.has(c))

  return {
    added,
    removed,
    current_commands: current.summary.commands_run,
    previous_commands: previous.summary.commands_run,
    current_findings: current.summary.total_findings,
    previous_findings: previous.summary.total_findings,
  }
}

// ---------------------------------------------------------------------------
// Register commands
// ---------------------------------------------------------------------------

export function registerSessionCommands(program: Command): void {
  const sessionCmd = program
    .command('session')
    .description('Engagement session manager — preserve context across multi-step assessments')

  // opensec session start --target <target> --name <name>
  sessionCmd
    .command('start')
    .description('Start a new engagement session')
    .requiredOption('--target <target>', 'Target domain/IP/URL')
    .requiredOption('--name <name>', 'Session name (e.g., "Q2-pentest")')
    .action((opts: { target: string; name: string }) => {
      if (sessionExists(opts.name)) {
        process.stderr.write(chalk.red(`Session already exists: ${opts.name}\n`))
        process.stderr.write(chalk.gray('Choose a different name or stop the existing session first.\n'))
        process.exit(EXIT_CODES.RUNTIME_ERROR)
      }

      const existingActive = getActiveSessionName()
      if (existingActive) {
        process.stderr.write(chalk.yellow(`Warning: Replacing active session "${existingActive}" with "${opts.name}"\n`))
      }

      createSession(opts.name, opts.target)
      setActiveSessionName(opts.name)

      process.stderr.write(chalk.green(`Session started: ${opts.name}\n`))
      process.stderr.write(chalk.gray(`Target: ${opts.target}\n`))
      process.stderr.write(chalk.gray('All commands will now be recorded to this session.\n'))
    })

  // opensec session stop
  sessionCmd
    .command('stop')
    .description('Stop the active session')
    .action(() => {
      const { name, session } = requireActiveSession()

      const completedSession: Session = {
        ...session,
        status: 'completed',
        updatedAt: new Date().toISOString(),
      }
      saveSession(completedSession)
      clearActiveSession()

      process.stderr.write(chalk.green(`Session completed: ${name}\n`))
      process.stderr.write(chalk.gray(`Commands run: ${session.summary.commands_run}\n`))
      process.stderr.write(chalk.gray(`Total findings: ${session.summary.total_findings}\n`))
      process.stderr.write(chalk.gray(`Duration: ${formatDuration(session.summary.duration_ms)}\n`))
    })

  // opensec session status
  sessionCmd
    .command('status')
    .description('Show current session progress')
    .action(() => {
      const { session } = requireActiveSession()
      const format = getFormat(program)

      process.stderr.write(`\n${chalk.bold('Active Session:')} ${session.name}\n`)
      process.stderr.write(`${chalk.gray('Target:')} ${session.target}\n`)
      process.stderr.write(`${chalk.gray('Status:')} ${session.status}\n`)
      process.stderr.write(`${chalk.gray('Started:')} ${session.createdAt}\n`)
      process.stderr.write(`${chalk.gray('Commands run:')} ${session.summary.commands_run}\n`)
      process.stderr.write(`${chalk.gray('Total findings:')} ${session.summary.total_findings}\n`)
      process.stderr.write(`${chalk.gray('Duration:')} ${formatDuration(session.summary.duration_ms)}\n`)

      const severityEntries = Object.entries(session.summary.by_severity)
      if (severityEntries.length > 0) {
        process.stderr.write(`${chalk.gray('By severity:')}\n`)
        for (const [sev, count] of severityEntries) {
          process.stderr.write(`  ${sev}: ${count}\n`)
        }
      }

      process.stderr.write('\n')

      if (session.steps.length > 0) {
        render(
          session.steps.map(s => ({
            command: s.command,
            findings: s.findings_count,
            duration: formatDuration(s.duration_ms),
            timestamp: s.timestamp,
          })),
          {
            format: format as 'table' | 'json' | 'csv' | 'yaml' | 'markdown',
            columns: ['command', 'findings', 'duration', 'timestamp'],
          },
        )
      }
    })

  // opensec session list
  sessionCmd
    .command('list')
    .description('List all sessions')
    .action(() => {
      const sessions = listSessions()
      const format = getFormat(program)

      if (sessions.length === 0) {
        process.stderr.write('No sessions found. Run: opensec session start --target <target> --name <name>\n')
        return
      }

      const activeName = getActiveSessionName()

      render(
        sessions.map(s => ({
          name: s.name,
          target: s.target,
          status: s.name === activeName ? 'active (current)' : s.status,
          commands: s.summary.commands_run,
          findings: s.summary.total_findings,
          duration: formatDuration(s.summary.duration_ms),
          created: s.createdAt,
        })),
        {
          format: format as 'table' | 'json' | 'csv' | 'yaml' | 'markdown',
          columns: ['name', 'target', 'status', 'commands', 'findings', 'duration', 'created'],
        },
      )
    })

  // opensec session report [--format html|json]
  sessionCmd
    .command('report')
    .description('Generate session report')
    .option('--format <format>', 'Report format: html or json', 'html')
    .option('-o, --output <file>', 'Output file path')
    .action(async (opts: { format: string; output?: string }) => {
      const { name, session } = requireActiveSession()

      if (opts.format === 'json') {
        const report = buildSessionReportJson(session)
        const outputPath = opts.output ?? `${name}-report.json`
        await writeFile(outputPath, JSON.stringify(report, null, 2), 'utf-8')
        process.stderr.write(chalk.green(`JSON report generated: ${outputPath}\n`))
      } else if (opts.format === 'html') {
        const html = await buildSessionReportHtml(session)
        const outputPath = opts.output ?? `${name}-report.html`
        await writeFile(outputPath, html, 'utf-8')
        process.stderr.write(chalk.green(`HTML report generated: ${outputPath}\n`))
      } else {
        process.stderr.write(chalk.red(`Unsupported format: ${opts.format}. Use html or json.\n`))
        process.exit(EXIT_CODES.RUNTIME_ERROR)
      }
    })

  // opensec session diff --previous <name>
  sessionCmd
    .command('diff')
    .description('Compare current session with a previous session')
    .requiredOption('--previous <name>', 'Name of the previous session to compare against')
    .action((opts: { previous: string }) => {
      const { session: current } = requireActiveSession()

      const previous = loadSession(opts.previous)
      if (!previous) {
        process.stderr.write(chalk.red(`Previous session not found: ${opts.previous}\n`))
        process.exit(EXIT_CODES.RUNTIME_ERROR)
      }

      const diff = diffSessions(current, previous)
      const format = getFormat(program)

      process.stderr.write(`\n${chalk.bold('Session Diff')}\n`)
      process.stderr.write(`  Current:  ${current.name} (${diff.current_commands} commands, ${diff.current_findings} findings)\n`)
      process.stderr.write(`  Previous: ${previous.name} (${diff.previous_commands} commands, ${diff.previous_findings} findings)\n`)
      process.stderr.write(`  Finding delta: ${diff.current_findings - diff.previous_findings >= 0 ? '+' : ''}${diff.current_findings - diff.previous_findings}\n`)
      process.stderr.write('\n')

      const rows = [
        ...diff.added.map(c => ({ change: 'ADDED', command: c })),
        ...diff.removed.map(c => ({ change: 'REMOVED', command: c })),
      ]

      if (rows.length > 0) {
        render(rows, {
          format: format as 'table' | 'json' | 'csv' | 'yaml' | 'markdown',
          columns: ['change', 'command'],
        })
      } else {
        process.stderr.write(chalk.gray('No command differences found.\n'))
      }
    })
}
