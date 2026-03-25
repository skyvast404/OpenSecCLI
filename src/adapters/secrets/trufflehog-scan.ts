/**
 * TruffleHog secret scanner adapter.
 * Deep git history + entropy-based secret detection.
 * Source: pentest-secrets-exposure
 */

import { cli, Strategy } from '../../registry.js'
import type { ExecContext } from '../../types.js'
import { runTool, checkToolInstalled, parseJsonLines } from '../_utils/tool-runner.js'

export function parseTrufflehogOutput(stdout: string): Record<string, unknown>[] {
  return parseJsonLines(stdout).map((r) => {
    const meta = (r.SourceMetadata as Record<string, unknown>) ?? {}
    const data = (meta.Data as Record<string, unknown>) ?? {}
    const git = (data.Git as Record<string, unknown>) ?? {}

    const verified = (r.Verified as boolean) ?? false
    return {
      detector: r.DetectorName ?? r.DetectorType ?? '',
      file: git.file ?? '',
      commit: git.commit ?? '',
      line: git.line ?? 0,
      verified,
      raw_preview: ((r.Raw as string) ?? '').slice(0, 20) + '...',
      severity: verified ? 'critical' : 'high',
    }
  })
}

cli({
  provider: 'secrets',
  name: 'trufflehog-scan',
  description: 'Scan git repository for secrets using TruffleHog (entropy + pattern detection)',
  strategy: Strategy.FREE,
  args: {
    path: { type: 'string', required: true, help: 'Path to git repository' },
    only_verified: { type: 'boolean', default: false, help: 'Only show verified (active) secrets' },
  },
  columns: ['detector', 'file', 'commit', 'line', 'verified', 'raw_preview', 'severity'],
  timeout: 300,

  async func(ctx: ExecContext, args: Record<string, unknown>) {
    const path = args.path as string
    const onlyVerified = args.only_verified as boolean

    if (!(await checkToolInstalled('trufflehog'))) {
      throw new Error('trufflehog is not installed. Install: brew install trufflehog / go install github.com/trufflesecurity/trufflehog/v3@latest')
    }

    const thArgs = ['git', 'file://' + path, '--json', '--no-update']
    if (onlyVerified) thArgs.push('--only-verified')

    const result = await runTool({
      tool: 'trufflehog',
      args: thArgs,
      timeout: 300,
      allowNonZero: true,
    })

    const findings = parseTrufflehogOutput(result.stdout)
    ctx.log.info(`TruffleHog found ${findings.length} secrets (${findings.filter((f) => f.verified).length} verified)`)
    return findings
  },
})
