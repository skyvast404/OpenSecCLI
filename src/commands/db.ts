/**
 * CLI commands for the security finding database.
 * Exposes history, diff, trends, and dismissal via `opensec db` subcommands.
 */

import type { Command } from 'commander'
import { render } from '../output.js'
import { queryFindings, getDiff, getTrend, dismissFinding, getDb } from '../db/store.js'
import type { Finding } from '../db/store.js'

function parseSinceDate(since?: string): string | undefined {
  if (!since) return undefined
  const match = since.match(/^(\d+)d$/)
  if (match) {
    const days = parseInt(match[1])
    return new Date(Date.now() - days * 86400000).toISOString()
  }
  return since // assume ISO date
}

function getFormat(program: Command): string {
  const globalOpts = program.opts()
  return globalOpts.json ? 'json' : (globalOpts.format ?? 'table')
}

function findingStatus(f: Finding): string {
  if (f.resolved_at) return 'resolved'
  if (f.dismissed) return 'dismissed'
  return 'active'
}

export function registerDbCommands(program: Command): void {
  const dbCmd = program
    .command('db')
    .description('Security finding database — history, diff, trends')

  // opensec db list [--target <target>] [--severity <sev>] [--since <date>] [--resolved] [--limit <n>]
  dbCmd
    .command('list')
    .description('List stored findings')
    .option('--target <target>', 'Filter by target')
    .option('--severity <severity>', 'Filter by severity: critical, high, medium, low, info')
    .option('--since <date>', 'Findings seen since date (ISO format or "7d", "30d")')
    .option('--resolved', 'Show resolved findings')
    .option('--dismissed', 'Include dismissed findings')
    .option('--limit <n>', 'Max results', '50')
    .action((opts: {
      target?: string
      severity?: string
      since?: string
      resolved?: boolean
      dismissed?: boolean
      limit: string
    }) => {
      const since = parseSinceDate(opts.since)
      const results = queryFindings({
        target: opts.target,
        severity: opts.severity,
        since,
        resolved: opts.resolved ? true : false,
        dismissed: opts.dismissed ? undefined : false,
        limit: parseInt(opts.limit),
      })

      const format = getFormat(program)
      render(
        results.map(r => ({
          fingerprint: (r.fingerprint as string).slice(0, 12) + '...',
          target: r.target,
          severity: r.severity,
          title: r.title,
          source: r.source,
          first_seen: r.first_seen_at,
          last_seen: r.last_seen_at,
          scans: r.scan_count,
          status: findingStatus(r),
        })),
        {
          format: format as 'table' | 'json' | 'csv' | 'yaml' | 'markdown',
          columns: ['fingerprint', 'severity', 'title', 'source', 'status', 'scans', 'last_seen'],
        },
      )
    })

  // opensec db diff --target <target> --since <date>
  dbCmd
    .command('diff')
    .description('Show finding changes since a date')
    .requiredOption('--target <target>', 'Target to diff')
    .option('--since <date>', 'Since date (default: 7d)', '7d')
    .action((opts: { target: string; since: string }) => {
      const since = parseSinceDate(opts.since) ?? new Date(Date.now() - 7 * 86400000).toISOString()
      const diff = getDiff(opts.target, since)

      process.stderr.write(`\nFinding diff for ${opts.target} since ${since}:\n`)
      process.stderr.write(`  New:       ${diff.new_findings.length}\n`)
      process.stderr.write(`  Resolved:  ${diff.resolved.length}\n`)
      process.stderr.write(`  Regressed: ${diff.regressed.length}\n`)
      process.stderr.write('\n')

      const format = getFormat(program)
      const all = [
        ...diff.new_findings.map(f => ({ change: 'NEW', severity: f.severity, title: f.title, source: f.source })),
        ...diff.resolved.map(f => ({ change: 'RESOLVED', severity: f.severity, title: f.title, source: f.source })),
        ...diff.regressed.map(f => ({ change: 'REGRESSED', severity: f.severity, title: f.title, source: f.source })),
      ]

      if (format === 'json') {
        process.stdout.write(
          JSON.stringify(
            {
              new: diff.new_findings,
              resolved: diff.resolved,
              regressed: diff.regressed,
            },
            null,
            2,
          ) + '\n',
        )
      } else {
        render(all, {
          format: format as 'table' | 'json' | 'csv' | 'yaml' | 'markdown',
          columns: ['change', 'severity', 'title', 'source'],
        })
      }
    })

  // opensec db trend --target <target> --period <days>
  dbCmd
    .command('trend')
    .description('Show finding trends over time')
    .requiredOption('--target <target>', 'Target to trend')
    .option('--period <days>', 'Period in days', '30')
    .action((opts: { target: string; period: string }) => {
      const days = parseInt(opts.period)
      const trend = getTrend(opts.target, days)
      const format = getFormat(program)
      render(trend, {
        format: format as 'table' | 'json' | 'csv' | 'yaml' | 'markdown',
        columns: ['date', 'total_findings', 'scan_count'],
      })
    })

  // opensec db dismiss <fingerprint> --reason <reason>
  dbCmd
    .command('dismiss <fingerprint>')
    .description('Dismiss a finding as false positive or accepted risk')
    .requiredOption('--reason <reason>', 'Reason for dismissal')
    .action((fp: string, opts: { reason: string }) => {
      const success = dismissFinding(fp, opts.reason)
      if (success) {
        process.stderr.write(`Finding ${fp} dismissed: ${opts.reason}\n`)
      } else {
        process.stderr.write(`Finding not found: ${fp}\n`)
        process.exit(1)
      }
    })

  // opensec db stats
  dbCmd
    .command('stats')
    .description('Show database statistics')
    .action(() => {
      const db = getDb()
      const stats = db.prepare(`
        SELECT
          COUNT(*) as total,
          SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) as critical,
          SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END) as high,
          SUM(CASE WHEN severity = 'medium' THEN 1 ELSE 0 END) as medium,
          SUM(CASE WHEN severity = 'low' THEN 1 ELSE 0 END) as low,
          SUM(CASE WHEN resolved_at IS NOT NULL THEN 1 ELSE 0 END) as resolved,
          SUM(CASE WHEN dismissed = 1 THEN 1 ELSE 0 END) as dismissed,
          COUNT(DISTINCT target) as targets
        FROM findings
      `).get() as Record<string, unknown>

      const scanCount = db.prepare('SELECT COUNT(*) as count FROM scans').get() as Record<string, unknown>

      const format = getFormat(program)
      render([{ ...stats, total_scans: scanCount.count }], {
        format: format as 'table' | 'json' | 'csv' | 'yaml' | 'markdown',
      })
    })
}
