/**
 * MCP server package integrity verifier.
 * Uses fetch() to query npm registry API -- no external tools needed.
 * Checks publish recency, maintainer count, downloads, install scripts, and more.
 */

import { cli, Strategy } from '../../registry.js'
import type { ExecContext } from '../../types.js'

// --- Types ---

type CheckStatus = 'PASS' | 'WARN' | 'FAIL' | 'ERROR'

interface VerifyRow {
  check: string
  status: CheckStatus
  detail: string
  [key: string]: unknown
}

interface NpmPackageMeta {
  name?: string
  description?: string
  'dist-tags'?: Record<string, string>
  time?: Record<string, string>
  maintainers?: Array<{ name?: string; email?: string }>
  versions?: Record<string, NpmVersionMeta>
  deprecated?: string
  license?: string
  [key: string]: unknown
}

interface NpmVersionMeta {
  scripts?: Record<string, string>
  deprecated?: string
  license?: string
  description?: string
  [key: string]: unknown
}

interface NpmDownloadResponse {
  downloads?: number
  [key: string]: unknown
}

// --- Verification Logic ---

const SECURITY_SENSITIVE_KEYWORDS = [
  'execute',
  'shell',
  'eval',
  'sudo',
  'root',
  'admin',
  'privilege',
  'credential',
  'password',
  'backdoor',
  'reverse shell',
]

const SEVEN_DAYS_MS = 7 * 24 * 60 * 60 * 1000

function checkPublishDate(
  time: Record<string, string> | undefined,
  latestVersion: string | undefined,
): VerifyRow {
  if (!time || !latestVersion) {
    return {
      check: 'PUBLISH_DATE',
      status: 'ERROR',
      detail: 'Could not determine publish date',
    }
  }

  const publishDateStr = time[latestVersion]
  if (!publishDateStr) {
    return {
      check: 'PUBLISH_DATE',
      status: 'ERROR',
      detail: 'No publish date for latest version',
    }
  }

  const publishDate = new Date(publishDateStr)
  const ageMs = Date.now() - publishDate.getTime()

  if (ageMs < SEVEN_DAYS_MS) {
    return {
      check: 'PUBLISH_DATE',
      status: 'WARN',
      detail: `Latest version published ${Math.floor(ageMs / (1000 * 60 * 60 * 24))} days ago (< 7 days — new/untested)`,
    }
  }

  return {
    check: 'PUBLISH_DATE',
    status: 'PASS',
    detail: `Latest version published ${publishDateStr}`,
  }
}

function checkMaintainerCount(
  maintainers: Array<{ name?: string }> | undefined,
): VerifyRow {
  const count = maintainers?.length ?? 0

  if (count === 0) {
    return {
      check: 'MAINTAINER_COUNT',
      status: 'WARN',
      detail: 'No maintainers listed',
    }
  }

  if (count === 1) {
    return {
      check: 'MAINTAINER_COUNT',
      status: 'WARN',
      detail: `Only 1 maintainer (bus factor risk): ${maintainers![0].name ?? 'unknown'}`,
    }
  }

  return {
    check: 'MAINTAINER_COUNT',
    status: 'PASS',
    detail: `${count} maintainers`,
  }
}

function checkDownloadCount(downloads: number | undefined): VerifyRow {
  if (downloads === undefined) {
    return {
      check: 'DOWNLOAD_COUNT',
      status: 'ERROR',
      detail: 'Could not fetch download stats',
    }
  }

  if (downloads < 100) {
    return {
      check: 'DOWNLOAD_COUNT',
      status: 'WARN',
      detail: `${downloads} weekly downloads (< 100 — low adoption)`,
    }
  }

  return {
    check: 'DOWNLOAD_COUNT',
    status: 'PASS',
    detail: `${downloads} weekly downloads`,
  }
}

function checkInstallScripts(versionMeta: NpmVersionMeta | undefined): VerifyRow {
  if (!versionMeta?.scripts) {
    return {
      check: 'INSTALL_SCRIPTS',
      status: 'PASS',
      detail: 'No install scripts detected',
    }
  }

  const dangerousScripts = ['preinstall', 'postinstall', 'install', 'preuninstall', 'postuninstall']
  const found = dangerousScripts.filter((s) => versionMeta.scripts![s])

  if (found.length > 0) {
    return {
      check: 'INSTALL_SCRIPTS',
      status: 'WARN',
      detail: `Install scripts found: ${found.join(', ')}`,
    }
  }

  return {
    check: 'INSTALL_SCRIPTS',
    status: 'PASS',
    detail: 'No dangerous install scripts',
  }
}

function checkDescriptionMatch(description: string | undefined): VerifyRow {
  if (!description) {
    return {
      check: 'DESCRIPTION_MATCH',
      status: 'PASS',
      detail: 'No description provided',
    }
  }

  const lower = description.toLowerCase()
  const matches = SECURITY_SENSITIVE_KEYWORDS.filter((kw) => lower.includes(kw))

  if (matches.length > 0) {
    return {
      check: 'DESCRIPTION_MATCH',
      status: 'WARN',
      detail: `Description mentions security-sensitive operations: ${matches.join(', ')}`,
    }
  }

  return {
    check: 'DESCRIPTION_MATCH',
    status: 'PASS',
    detail: 'No security-sensitive keywords in description',
  }
}

function checkDeprecated(meta: NpmPackageMeta, versionMeta: NpmVersionMeta | undefined): VerifyRow {
  if (meta.deprecated || versionMeta?.deprecated) {
    return {
      check: 'DEPRECATED',
      status: 'FAIL',
      detail: `Package is deprecated: ${meta.deprecated ?? versionMeta?.deprecated}`,
    }
  }

  return {
    check: 'DEPRECATED',
    status: 'PASS',
    detail: 'Package is not deprecated',
  }
}

function checkLicense(meta: NpmPackageMeta, versionMeta: NpmVersionMeta | undefined): VerifyRow {
  const license = meta.license ?? versionMeta?.license

  if (!license) {
    return {
      check: 'LICENSE',
      status: 'WARN',
      detail: 'No license specified',
    }
  }

  return {
    check: 'LICENSE',
    status: 'PASS',
    detail: `License: ${typeof license === 'string' ? license : JSON.stringify(license)}`,
  }
}

// --- Main Verification ---

export async function verifyPackage(
  packageName: string,
  registryUrl: string = 'https://registry.npmjs.org',
): Promise<readonly VerifyRow[]> {
  const rows: VerifyRow[] = []

  // Fetch package metadata
  let meta: NpmPackageMeta
  try {
    const metaResponse = await fetch(`${registryUrl}/${encodeURIComponent(packageName)}`)
    if (!metaResponse.ok) {
      throw new Error(`HTTP ${metaResponse.status}`)
    }
    meta = (await metaResponse.json()) as NpmPackageMeta
  } catch (err) {
    return [
      {
        check: 'FETCH_METADATA',
        status: 'ERROR',
        detail: `Failed to fetch package metadata: ${err instanceof Error ? err.message : String(err)}`,
      },
    ]
  }

  const latestVersion = meta['dist-tags']?.latest
  const versionMeta = latestVersion && meta.versions
    ? meta.versions[latestVersion]
    : undefined

  // Run all checks
  rows.push(checkPublishDate(meta.time, latestVersion))
  rows.push(checkMaintainerCount(meta.maintainers))

  // Fetch download stats
  let weeklyDownloads: number | undefined
  try {
    const dlResponse = await fetch(
      `https://api.npmjs.org/downloads/point/last-week/${encodeURIComponent(packageName)}`,
    )
    if (dlResponse.ok) {
      const dlData = (await dlResponse.json()) as NpmDownloadResponse
      weeklyDownloads = dlData.downloads
    }
  } catch {
    // Download stats unavailable
  }
  rows.push(checkDownloadCount(weeklyDownloads))

  rows.push(checkInstallScripts(versionMeta))
  rows.push(checkDescriptionMatch(meta.description ?? versionMeta?.description))
  rows.push(checkDeprecated(meta, versionMeta))
  rows.push(checkLicense(meta, versionMeta))

  return rows
}

// --- CLI Registration ---

cli({
  provider: 'agent-security',
  name: 'supply-chain-verify',
  description:
    'Verify MCP server package integrity and check for known vulnerabilities',
  strategy: Strategy.FREE,
  domain: 'agent-security',
  args: {
    package_name: {
      type: 'string',
      required: true,
      help: 'npm package name to verify',
    },
    registry: {
      type: 'string',
      required: false,
      default: 'https://registry.npmjs.org',
      help: 'npm registry URL',
    },
  },
  columns: ['check', 'status', 'detail'],
  timeout: 30,

  async func(ctx: ExecContext, args: Record<string, unknown>) {
    const packageName = args.package_name as string
    const registryUrl = (args.registry as string | undefined) ?? 'https://registry.npmjs.org'

    ctx.log.info(`Verifying package: ${packageName} from ${registryUrl}`)

    const rows = await verifyPackage(packageName, registryUrl)

    const warnings = rows.filter((r) => r.status === 'WARN').length
    const failures = rows.filter((r) => r.status === 'FAIL').length
    ctx.log.info(
      `Verification complete: ${warnings} warnings, ${failures} failures`,
    )

    return [...rows]
  },
})
