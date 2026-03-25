/**
 * Android APK static analysis adapter.
 * Wraps: aapt2/aapt (metadata) + strings (secret detection)
 * Source: pentest-mobile-app
 */

import { existsSync } from 'node:fs'
import { cli, Strategy } from '../../registry.js'
import type { ExecContext } from '../../types.js'
import { runTool, findAvailableTool, checkToolInstalled } from '../_utils/tool-runner.js'

cli({
  provider: 'forensics',
  name: 'apk-analyze',
  description: 'Analyze Android APK for security issues (permissions, exported components, hardcoded secrets)',
  strategy: Strategy.FREE,
  args: {
    apk: { type: 'string', required: true, help: 'Path to APK file' },
  },
  columns: ['category', 'finding', 'severity', 'detail'],
  timeout: 120,

  async func(ctx: ExecContext, args: Record<string, unknown>) {
    const apk = args.apk as string
    if (!existsSync(apk)) {
      throw new Error(`APK file not found: ${apk}`)
    }
    const results: Record<string, unknown>[] = []

    // aapt2 for manifest info
    const aapt = await findAvailableTool(['aapt2', 'aapt'])
    if (aapt) {
      try {
        const r = await runTool({ tool: aapt, args: ['dump', 'badging', apk] })
        const lines = r.stdout.split('\n')

        // Extract permissions
        const perms = lines.filter((l) => l.startsWith('uses-permission:'))
        const dangerousPerms = perms.filter((p) =>
          p.includes('CAMERA') || p.includes('READ_CONTACTS') || p.includes('READ_SMS') ||
          p.includes('RECORD_AUDIO') || p.includes('ACCESS_FINE_LOCATION') || p.includes('READ_PHONE_STATE') ||
          p.includes('INTERNET') || p.includes('READ_EXTERNAL_STORAGE'),
        )
        for (const perm of dangerousPerms) {
          const name = perm.match(/name='([^']+)'/)?.[1] ?? perm
          results.push({
            category: 'permission',
            finding: name,
            severity: name.includes('SMS') || name.includes('CONTACTS') ? 'high' : 'medium',
            detail: 'Dangerous permission requested',
          })
        }

        // Check debuggable
        if (lines.some((l) => l.includes("application-debuggable='true'"))) {
          results.push({
            category: 'config',
            finding: 'Debuggable APK',
            severity: 'critical',
            detail: 'android:debuggable=true allows runtime debugging and data extraction',
          })
        }

        // Check backup allowed
        if (lines.some((l) => l.includes("allowBackup='true'"))) {
          results.push({
            category: 'config',
            finding: 'Backup allowed',
            severity: 'medium',
            detail: 'android:allowBackup=true allows data extraction via adb backup',
          })
        }

        // Target SDK
        const sdkMatch = lines.find((l) => l.includes('targetSdkVersion'))
        if (sdkMatch) {
          const ver = parseInt(sdkMatch.match(/\d+/)?.[0] ?? '0')
          if (ver < 30) {
            results.push({
              category: 'config',
              finding: `Low targetSdkVersion (${ver})`,
              severity: 'medium',
              detail: 'Old SDK target may lack modern security features (scoped storage, etc.)',
            })
          }
        }
      } catch (e) { ctx.log.warn(`aapt analysis failed: ${(e as Error).message}`) }
    }

    // Check for hardcoded strings in DEX
    if (await checkToolInstalled('strings')) {
      try {
        const r = await runTool({ tool: 'strings', args: ['-n', '10', apk] })
        const secrets = r.stdout.split('\n').filter((s) =>
          s.match(/(api[_-]?key|secret|password|token|auth|firebase|aws|gcp)/i) &&
          !s.match(/^[A-Z_]+$/) && s.length < 200,
        )
        for (const secret of secrets.slice(0, 10)) {
          results.push({
            category: 'secret',
            finding: 'Potential hardcoded secret',
            severity: 'high',
            detail: secret.slice(0, 100),
          })
        }
      } catch { /* skip */ }
    }

    ctx.log.info(`APK analysis: ${results.length} findings`)
    return results
  },
})
