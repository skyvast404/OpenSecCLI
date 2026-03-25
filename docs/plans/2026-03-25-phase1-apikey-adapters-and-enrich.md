# Phase 1: API Key Adapters + Multi-Source Enrichment Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add API-key-based adapters (AbuseIPDB, VirusTotal, GreyNoise, ipinfo, Shodan) and the killer feature — multi-source `enrich` pipeline step that queries N APIs in parallel and produces a consensus verdict.

**Architecture:** New `enrich` pipeline step dispatches to existing registered adapters in parallel via `Promise.allSettled`, collects results per source, and applies configurable consensus rules. Auth test command validates stored keys. Each API Key adapter is a standard YAML file using `{{ auth.api_key }}`.

**Tech Stack:** TypeScript, YAML adapters, Node.js native fetch, vitest

---

## Pre-requisites

- Phase 0 framework is functional (`npx tsx src/main.ts list` shows 8 adapters)
- `npm install` has been run
- Tests can be run with `npx vitest run`

---

### Task 1: Template Engine — Support Nested Dot Paths for Deep JSON

**Why:** NVD adapter works but VT/AbuseIPDB responses have deeply nested JSON (e.g., `item.data.attributes.last_analysis_stats.malicious`). The current template `walkPath` handles simple nesting but some APIs return arrays-of-objects that need `item.data.0.field`.

**Files:**
- Modify: `src/pipeline/template.ts:walkPath` (line ~138)
- Test: `tests/unit/template.test.ts` (create)

**Step 1: Write the failing test**

```typescript
// tests/unit/template.test.ts
import { describe, it, expect } from 'vitest'
import { renderTemplate, evaluateExpression } from '../../src/pipeline/template.js'

describe('template engine', () => {
  const ctx = {
    args: { ip: '1.2.3.4', limit: 10 },
    auth: { api_key: 'test-key' },
    item: {
      data: {
        attributes: {
          last_analysis_stats: { malicious: 5, suspicious: 2 },
          tags: ['malware', 'trojan'],
        },
      },
      nested: [{ name: 'first' }, { name: 'second' }],
    },
    index: 0,
  }

  it('resolves deep nested paths', () => {
    const result = evaluateExpression('item.data.attributes.last_analysis_stats.malicious', ctx)
    expect(result).toBe(5)
  })

  it('resolves array index in path', () => {
    const result = evaluateExpression('item.nested.0.name', ctx)
    expect(result).toBe('first')
  })

  it('renders template with nested access', () => {
    const result = renderTemplate('score={{ item.data.attributes.last_analysis_stats.malicious }}', ctx)
    expect(result).toBe('score=5')
  })

  it('applies join filter to array', () => {
    const result = renderTemplate('{{ item.data.attributes.tags | join(", ") }}', ctx)
    expect(result).toBe('malware, trojan')
  })

  it('handles missing paths gracefully', () => {
    const result = evaluateExpression('item.data.nonexistent.deep.path', ctx)
    expect(result).toBeUndefined()
  })

  it('resolves args and auth', () => {
    expect(evaluateExpression('args.ip', ctx)).toBe('1.2.3.4')
    expect(evaluateExpression('auth.api_key', ctx)).toBe('test-key')
  })

  it('evaluates ternary', () => {
    const result = evaluateExpression("item.data.attributes.last_analysis_stats.malicious > 3 ? 'HIGH' : 'LOW'", ctx)
    expect(result).toBe('HIGH')
  })

  it('evaluates logical OR default', () => {
    const result = evaluateExpression("item.data.nonexistent || 'N/A'", ctx)
    expect(result).toBe('N/A')
  })
})
```

**Step 2: Run test to verify it fails/passes**

Run: `npx vitest run tests/unit/template.test.ts`
Expected: Some tests may pass already, others may fail on deep nested array access.

**Step 3: Fix any failing tests by adjusting walkPath**

In `src/pipeline/template.ts`, the `walkPath` function already handles arrays via numeric segment check. If tests pass already — great, no code changes needed. If `item.nested.0.name` fails, update `walkPath`:

```typescript
function walkPath(value: unknown, segments: string[]): unknown {
  for (const segment of segments) {
    if (value === null || value === undefined) return undefined
    if (Array.isArray(value) && /^\d+$/.test(segment)) {
      value = value[parseInt(segment, 10)]
    } else if (typeof value === 'object') {
      value = (value as Record<string, unknown>)[segment]
    } else {
      return undefined
    }
  }
  return value
}
```

**Step 4: Run test to verify all pass**

Run: `npx vitest run tests/unit/template.test.ts`
Expected: 8 tests PASS

**Step 5: Commit**

```bash
git add tests/unit/template.test.ts src/pipeline/template.ts
git commit -m "test: add template engine unit tests, fix deep path resolution"
```

---

### Task 2: Auth Test Command

**Why:** Users need to verify their API keys work before using adapters. `opensec auth test <provider>` should hit a lightweight endpoint and confirm connectivity.

**Files:**
- Create: `src/auth/test.ts`
- Modify: `src/cli.ts` — add `auth test` subcommand
- Test: `tests/unit/auth-store.test.ts` (create)

**Step 1: Write the failing test for auth store**

```typescript
// tests/unit/auth-store.test.ts
import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { saveAuth, loadAuth, removeAuth, listAuth } from '../../src/auth/store.js'
import { mkdirSync, rmSync, existsSync } from 'fs'
import { join } from 'path'
import { tmpdir } from 'os'

describe('auth store', () => {
  const origHome = process.env['HOME']
  const testHome = join(tmpdir(), `opensec-test-${Date.now()}`)

  beforeEach(() => {
    mkdirSync(testHome, { recursive: true })
    process.env['HOME'] = testHome
  })

  afterEach(() => {
    process.env['HOME'] = origHome
    if (existsSync(testHome)) rmSync(testHome, { recursive: true, force: true })
  })

  it('saves and loads credentials', () => {
    saveAuth('testprovider', { api_key: 'sk-123' })
    const creds = loadAuth('testprovider')
    expect(creds).toEqual({ api_key: 'sk-123' })
  })

  it('returns null for missing provider', () => {
    expect(loadAuth('nonexistent')).toBeNull()
  })

  it('prefers env var over file', () => {
    saveAuth('testprovider', { api_key: 'from-file' })
    process.env['OPENSECCLI_TESTPROVIDER_API_KEY'] = 'from-env'
    const creds = loadAuth('testprovider')
    expect(creds).toEqual({ api_key: 'from-env' })
    delete process.env['OPENSECCLI_TESTPROVIDER_API_KEY']
  })

  it('removes credentials', () => {
    saveAuth('testprovider', { api_key: 'sk-123' })
    expect(removeAuth('testprovider')).toBe(true)
    expect(loadAuth('testprovider')).toBeNull()
  })

  it('lists configured providers', () => {
    saveAuth('provider-a', { api_key: 'a' })
    saveAuth('provider-b', { api_key: 'b' })
    const providers = listAuth()
    expect(providers).toContain('provider-a')
    expect(providers).toContain('provider-b')
  })
})
```

**Step 2: Run test**

Run: `npx vitest run tests/unit/auth-store.test.ts`
Expected: PASS (auth store already implemented)

**Step 3: Create auth test module**

```typescript
// src/auth/test.ts
import { PROVIDER_DOMAINS } from '../constants.js'

interface TestEndpoint {
  url: string
  headers: Record<string, string>
  expectStatus: number[]
}

const TEST_ENDPOINTS: Record<string, (apiKey: string) => TestEndpoint> = {
  abuseipdb: (key) => ({
    url: 'https://api.abuseipdb.com/api/v2/check?ipAddress=8.8.8.8&maxAgeInDays=1',
    headers: { Key: key, Accept: 'application/json' },
    expectStatus: [200],
  }),
  virustotal: (key) => ({
    url: 'https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8',
    headers: { 'x-apikey': key, Accept: 'application/json' },
    expectStatus: [200],
  }),
  greynoise: (key) => ({
    url: 'https://api.greynoise.io/v3/community/8.8.8.8',
    headers: { key: key, Accept: 'application/json' },
    expectStatus: [200, 404],  // 404 = IP not found, but auth worked
  }),
  shodan: (key) => ({
    url: `https://api.shodan.io/api-info?key=${key}`,
    headers: { Accept: 'application/json' },
    expectStatus: [200],
  }),
  ipinfo: (key) => ({
    url: 'https://ipinfo.io/8.8.8.8/json',
    headers: { Authorization: `Bearer ${key}`, Accept: 'application/json' },
    expectStatus: [200],
  }),
}

export async function testAuth(
  provider: string,
  apiKey: string,
): Promise<{ ok: boolean; status: number; message: string }> {
  const buildEndpoint = TEST_ENDPOINTS[provider]
  if (!buildEndpoint) {
    return { ok: false, status: 0, message: `No test endpoint configured for ${provider}` }
  }

  const endpoint = buildEndpoint(apiKey)

  try {
    const response = await fetch(endpoint.url, {
      headers: endpoint.headers,
      signal: AbortSignal.timeout(10_000),
    })

    const ok = endpoint.expectStatus.includes(response.status)
    return {
      ok,
      status: response.status,
      message: ok ? 'Authentication successful' : `HTTP ${response.status} — check your API key`,
    }
  } catch (error) {
    return {
      ok: false,
      status: 0,
      message: `Connection failed: ${(error as Error).message}`,
    }
  }
}
```

**Step 4: Wire into CLI**

In `src/cli.ts`, add after the existing `auth remove` command:

```typescript
  authCmd
    .command('test <provider>')
    .description('Test API key connectivity for a provider')
    .action(async (provider: string) => {
      const creds = loadAuth(provider)
      if (!creds?.api_key) {
        process.stderr.write(chalk.red(`No API key configured for ${provider}\n`))
        process.stderr.write(chalk.gray(`Run: opensec auth add ${provider} --api-key\n`))
        process.exit(EXIT_CODES.AUTH_FAILED)
      }

      process.stderr.write(`Testing ${provider}...`)
      const { testAuth } = await import('./auth/test.js')
      const result = await testAuth(provider, creds.api_key)

      if (result.ok) {
        process.stderr.write(chalk.green(` ✓ ${result.message}\n`))
      } else {
        process.stderr.write(chalk.red(` ✗ ${result.message}\n`))
        process.exit(EXIT_CODES.AUTH_FAILED)
      }
    })
```

Add import at top of `src/cli.ts`:

```typescript
import { loadAuth, saveAuth, removeAuth, listAuth } from './auth/index.js'
```

Also update `src/auth/index.ts`:

```typescript
export { loadAuth, saveAuth, removeAuth, listAuth } from './store.js'
export { testAuth } from './test.js'
```

**Step 5: Manual test**

Run: `npx tsx src/main.ts auth test nonexistent`
Expected: Red error "No API key configured for nonexistent"

**Step 6: Commit**

```bash
git add src/auth/test.ts src/auth/index.ts src/cli.ts tests/unit/auth-store.test.ts
git commit -m "feat: auth test command + auth store unit tests"
```

---

### Task 3: AbuseIPDB Adapter

**Files:**
- Create: `src/adapters/abuseipdb/ip-check.yaml`
- Test: `tests/adapter/abuseipdb.test.ts`

**Step 1: Write the adapter test**

```typescript
// tests/adapter/abuseipdb.test.ts
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { executePipeline } from '../../src/pipeline/executor.js'
import YAML from 'js-yaml'
import { readFileSync } from 'fs'
import { join, dirname } from 'path'
import { fileURLToPath } from 'url'

const __dirname = dirname(fileURLToPath(import.meta.url))

const MOCK_RESPONSE = {
  data: {
    ipAddress: '185.220.101.34',
    isPublic: true,
    abuseConfidenceScore: 100,
    countryCode: 'DE',
    isp: 'Hetzner Online GmbH',
    usageType: 'Data Center/Web Hosting/Transit',
    domain: 'hetzner.com',
    totalReports: 847,
    lastReportedAt: '2026-03-20T12:00:00+00:00',
  },
}

describe('abuseipdb/ip-check', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true,
      headers: new Headers({ 'content-type': 'application/json' }),
      json: () => Promise.resolve(MOCK_RESPONSE),
    }))
  })

  it('transforms API response into expected columns', async () => {
    const yamlPath = join(__dirname, '../../src/adapters/abuseipdb/ip-check.yaml')
    const def = YAML.load(readFileSync(yamlPath, 'utf-8')) as any

    const result = await executePipeline(def.pipeline, {
      args: { ip: '185.220.101.34', days: 90 },
      auth: { api_key: 'test-key' },
    })

    expect(result).toBeDefined()
    const row = Array.isArray(result) ? result[0] : result
    expect(row).toHaveProperty('ip', '185.220.101.34')
    expect(row).toHaveProperty('abuse_score', 100)
    expect(row).toHaveProperty('country', 'DE')
    expect(row).toHaveProperty('total_reports', 847)
  })
})
```

**Step 2: Run test to verify it fails**

Run: `npx vitest run tests/adapter/abuseipdb.test.ts`
Expected: FAIL — adapter file doesn't exist yet

**Step 3: Write the YAML adapter**

```yaml
# src/adapters/abuseipdb/ip-check.yaml
provider: abuseipdb
name: ip-check
description: Check IP reputation on AbuseIPDB
strategy: API_KEY
auth: abuseipdb

args:
  ip:
    type: string
    required: true
    help: IP address to check
  days:
    type: number
    default: 90
    help: Max age of reports in days

pipeline:
  - request:
      url: https://api.abuseipdb.com/api/v2/check
      headers:
        Key: "{{ auth.api_key }}"
        Accept: application/json
      params:
        ipAddress: "{{ args.ip }}"
        maxAgeInDays: "{{ args.days }}"

  - select:
      path: data

  - map:
      template:
        ip: "{{ item.ipAddress }}"
        abuse_score: "{{ item.abuseConfidenceScore }}"
        country: "{{ item.countryCode }}"
        isp: "{{ item.isp }}"
        usage_type: "{{ item.usageType }}"
        domain: "{{ item.domain }}"
        total_reports: "{{ item.totalReports }}"
        last_reported: "{{ item.lastReportedAt }}"

columns: [ip, abuse_score, country, isp, total_reports, last_reported]
```

**Step 4: Run test to verify it passes**

Run: `npx vitest run tests/adapter/abuseipdb.test.ts`
Expected: PASS

**Step 5: Commit**

```bash
git add src/adapters/abuseipdb/ tests/adapter/abuseipdb.test.ts
git commit -m "feat: add abuseipdb ip-check adapter"
```

---

### Task 4: VirusTotal Adapters (hash, IP, domain)

**Files:**
- Create: `src/adapters/virustotal/hash-lookup.yaml`
- Create: `src/adapters/virustotal/ip-lookup.yaml`
- Create: `src/adapters/virustotal/domain-lookup.yaml`
- Test: `tests/adapter/virustotal.test.ts`

**Step 1: Write the adapter test**

```typescript
// tests/adapter/virustotal.test.ts
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { executePipeline } from '../../src/pipeline/executor.js'
import YAML from 'js-yaml'
import { readFileSync } from 'fs'
import { join, dirname } from 'path'
import { fileURLToPath } from 'url'

const __dirname = dirname(fileURLToPath(import.meta.url))

const MOCK_IP_RESPONSE = {
  data: {
    id: '8.8.8.8',
    attributes: {
      country: 'US',
      as_owner: 'GOOGLE',
      asn: 15169,
      last_analysis_stats: { malicious: 0, suspicious: 0, harmless: 85, undetected: 5 },
      network: '8.8.8.0/24',
      tags: [],
    },
  },
}

describe('virustotal/ip-lookup', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true,
      headers: new Headers({ 'content-type': 'application/json' }),
      json: () => Promise.resolve(MOCK_IP_RESPONSE),
    }))
  })

  it('transforms VT IP response', async () => {
    const yamlPath = join(__dirname, '../../src/adapters/virustotal/ip-lookup.yaml')
    const def = YAML.load(readFileSync(yamlPath, 'utf-8')) as any

    const result = await executePipeline(def.pipeline, {
      args: { ip: '8.8.8.8' },
      auth: { api_key: 'test-key' },
    })

    const row = Array.isArray(result) ? result[0] : result
    expect(row).toHaveProperty('ip', '8.8.8.8')
    expect(row).toHaveProperty('country', 'US')
    expect(row).toHaveProperty('as_owner', 'GOOGLE')
    expect(row).toHaveProperty('malicious', 0)
  })
})
```

**Step 2: Run test to verify it fails**

Run: `npx vitest run tests/adapter/virustotal.test.ts`
Expected: FAIL — file not found

**Step 3: Write the 3 YAML adapters**

```yaml
# src/adapters/virustotal/ip-lookup.yaml
provider: virustotal
name: ip-lookup
description: Look up IP address reputation on VirusTotal
strategy: API_KEY
auth: virustotal

args:
  ip:
    type: string
    required: true
    help: IP address to look up

pipeline:
  - request:
      url: "https://www.virustotal.com/api/v3/ip_addresses/{{ args.ip }}"
      headers:
        x-apikey: "{{ auth.api_key }}"
        Accept: application/json

  - map:
      template:
        ip: "{{ item.data.id }}"
        country: "{{ item.data.attributes.country }}"
        as_owner: "{{ item.data.attributes.as_owner }}"
        asn: "{{ item.data.attributes.asn }}"
        malicious: "{{ item.data.attributes.last_analysis_stats.malicious }}"
        suspicious: "{{ item.data.attributes.last_analysis_stats.suspicious }}"
        harmless: "{{ item.data.attributes.last_analysis_stats.harmless }}"
        network: "{{ item.data.attributes.network }}"

columns: [ip, country, as_owner, malicious, suspicious, harmless, network]
```

```yaml
# src/adapters/virustotal/hash-lookup.yaml
provider: virustotal
name: hash-lookup
description: Look up file hash on VirusTotal
strategy: API_KEY
auth: virustotal

args:
  hash:
    type: string
    required: true
    help: File hash (MD5, SHA1, or SHA256)

pipeline:
  - request:
      url: "https://www.virustotal.com/api/v3/files/{{ args.hash }}"
      headers:
        x-apikey: "{{ auth.api_key }}"
        Accept: application/json

  - map:
      template:
        sha256: "{{ item.data.attributes.sha256 }}"
        file_type: "{{ item.data.attributes.type_description }}"
        size: "{{ item.data.attributes.size }}"
        malicious: "{{ item.data.attributes.last_analysis_stats.malicious }}"
        suspicious: "{{ item.data.attributes.last_analysis_stats.suspicious }}"
        undetected: "{{ item.data.attributes.last_analysis_stats.undetected }}"
        name: "{{ item.data.attributes.meaningful_name }}"
        tags: "{{ item.data.attributes.tags | join(', ') }}"
        first_seen: "{{ item.data.attributes.first_submission_date }}"

columns: [sha256, file_type, name, malicious, suspicious, undetected, tags]
```

```yaml
# src/adapters/virustotal/domain-lookup.yaml
provider: virustotal
name: domain-lookup
description: Look up domain reputation on VirusTotal
strategy: API_KEY
auth: virustotal

args:
  domain:
    type: string
    required: true
    help: Domain name to look up

pipeline:
  - request:
      url: "https://www.virustotal.com/api/v3/domains/{{ args.domain }}"
      headers:
        x-apikey: "{{ auth.api_key }}"
        Accept: application/json

  - map:
      template:
        domain: "{{ item.data.id }}"
        registrar: "{{ item.data.attributes.registrar }}"
        creation_date: "{{ item.data.attributes.creation_date }}"
        malicious: "{{ item.data.attributes.last_analysis_stats.malicious }}"
        suspicious: "{{ item.data.attributes.last_analysis_stats.suspicious }}"
        harmless: "{{ item.data.attributes.last_analysis_stats.harmless }}"
        reputation: "{{ item.data.attributes.reputation }}"
        categories: "{{ item.data.attributes.categories | values | join(', ') }}"

columns: [domain, registrar, malicious, suspicious, harmless, reputation, categories]
```

**Step 4: Run test to verify it passes**

Run: `npx vitest run tests/adapter/virustotal.test.ts`
Expected: PASS

**Step 5: Commit**

```bash
git add src/adapters/virustotal/ tests/adapter/virustotal.test.ts
git commit -m "feat: add virustotal adapters (hash-lookup, ip-lookup, domain-lookup)"
```

---

### Task 5: GreyNoise + ipinfo + Shodan Adapters

**Files:**
- Create: `src/adapters/greynoise/ip-check.yaml`
- Create: `src/adapters/ipinfo/ip-lookup.yaml`
- Create: `src/adapters/shodan/host-lookup.yaml`

**Step 1: Write GreyNoise adapter**

```yaml
# src/adapters/greynoise/ip-check.yaml
provider: greynoise
name: ip-check
description: Check IP noise classification on GreyNoise
strategy: API_KEY
auth: greynoise

args:
  ip:
    type: string
    required: true
    help: IP address to check

pipeline:
  - request:
      url: "https://api.greynoise.io/v3/community/{{ args.ip }}"
      headers:
        key: "{{ auth.api_key }}"
        Accept: application/json

  - map:
      template:
        ip: "{{ item.ip }}"
        noise: "{{ item.noise }}"
        riot: "{{ item.riot }}"
        classification: "{{ item.classification }}"
        name: "{{ item.name }}"
        link: "{{ item.link }}"
        last_seen: "{{ item.last_seen }}"
        message: "{{ item.message }}"

columns: [ip, classification, noise, riot, name, last_seen]
```

**Step 2: Write ipinfo adapter**

```yaml
# src/adapters/ipinfo/ip-lookup.yaml
provider: ipinfo
name: ip-lookup
description: Get IP geolocation and ASN info from ipinfo.io
strategy: API_KEY
auth: ipinfo

args:
  ip:
    type: string
    required: true
    help: IP address to look up

pipeline:
  - request:
      url: "https://ipinfo.io/{{ args.ip }}/json"
      headers:
        Authorization: "Bearer {{ auth.api_key }}"
        Accept: application/json

  - map:
      template:
        ip: "{{ item.ip }}"
        city: "{{ item.city }}"
        region: "{{ item.region }}"
        country: "{{ item.country }}"
        org: "{{ item.org }}"
        postal: "{{ item.postal }}"
        timezone: "{{ item.timezone }}"
        loc: "{{ item.loc }}"

columns: [ip, city, region, country, org, timezone]
```

**Step 3: Write Shodan adapter**

```yaml
# src/adapters/shodan/host-lookup.yaml
provider: shodan
name: host-lookup
description: Look up host information on Shodan
strategy: API_KEY
auth: shodan

args:
  ip:
    type: string
    required: true
    help: IP address to look up

pipeline:
  - request:
      url: "https://api.shodan.io/shodan/host/{{ args.ip }}"
      params:
        key: "{{ auth.api_key }}"

  - map:
      template:
        ip: "{{ item.ip_str }}"
        org: "{{ item.org }}"
        os: "{{ item.os }}"
        isp: "{{ item.isp }}"
        country: "{{ item.country_code }}"
        city: "{{ item.city }}"
        ports: "{{ item.ports | join(', ') }}"
        vulns: "{{ item.vulns | join(', ') }}"
        last_update: "{{ item.last_update }}"

columns: [ip, org, os, country, city, ports, vulns]
```

**Step 4: Verify adapters load**

Run: `npx tsx src/main.ts list --json 2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d), 'adapters')"`
Expected: `14 adapters` (8 existing + 1 abuseipdb + 3 VT + 3 new)

**Step 5: Commit**

```bash
git add src/adapters/greynoise/ src/adapters/ipinfo/ src/adapters/shodan/
git commit -m "feat: add greynoise, ipinfo, shodan adapters"
```

---

### Task 6: Enrich Pipeline Step

**Why:** This is the killer feature. `opensec enrichment ip-enrich 1.2.3.4` should query AbuseIPDB + VT + GreyNoise + ipinfo + ThreatFox in parallel, merge results, and produce a consensus verdict.

**Files:**
- Create: `src/pipeline/steps/enrich.ts`
- Modify: `src/pipeline/executor.ts` — add `enrich` to step switch
- Test: `tests/unit/enrich.test.ts`

**Step 1: Write the failing test**

```typescript
// tests/unit/enrich.test.ts
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { executeEnrich } from '../../src/pipeline/steps/enrich.js'

describe('enrich step', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn().mockImplementation((url: string) => {
      if (url.includes('abuseipdb')) {
        return Promise.resolve({
          ok: true,
          headers: new Headers({ 'content-type': 'application/json' }),
          json: () => Promise.resolve({ data: { abuseConfidenceScore: 95, countryCode: 'DE' } }),
        })
      }
      if (url.includes('virustotal')) {
        return Promise.resolve({
          ok: true,
          headers: new Headers({ 'content-type': 'application/json' }),
          json: () => Promise.resolve({ data: { attributes: { last_analysis_stats: { malicious: 8 } } } }),
        })
      }
      if (url.includes('greynoise')) {
        return Promise.resolve({
          ok: true,
          headers: new Headers({ 'content-type': 'application/json' }),
          json: () => Promise.resolve({ classification: 'malicious', noise: true }),
        })
      }
      return Promise.resolve({
        ok: true,
        headers: new Headers({ 'content-type': 'application/json' }),
        json: () => Promise.resolve({}),
      })
    }))
  })

  it('queries multiple sources in parallel and merges results', async () => {
    const params = {
      sources: [
        { name: 'AbuseIPDB', url: 'https://api.abuseipdb.com/api/v2/check', headers: { Key: 'k1' }, params: { ipAddress: '1.2.3.4' }, select: 'data', fields: { abuse_score: 'abuseConfidenceScore', country: 'countryCode' } },
        { name: 'VirusTotal', url: 'https://www.virustotal.com/api/v3/ip_addresses/1.2.3.4', headers: { 'x-apikey': 'k2' }, fields: { malicious: 'data.attributes.last_analysis_stats.malicious' } },
        { name: 'GreyNoise', url: 'https://api.greynoise.io/v3/community/1.2.3.4', headers: { key: 'k3' }, fields: { classification: 'classification' } },
      ],
      timeout: 10,
    }

    const result = await executeEnrich(params, null, { args: {}, auth: {} })

    expect(Array.isArray(result)).toBe(true)
    expect(result.length).toBe(3)
    expect(result[0]).toHaveProperty('source', 'AbuseIPDB')
    expect(result[0]).toHaveProperty('abuse_score', 95)
    expect(result[1]).toHaveProperty('source', 'VirusTotal')
    expect(result[2]).toHaveProperty('source', 'GreyNoise')
    expect(result[2]).toHaveProperty('classification', 'malicious')
  })

  it('handles source failures gracefully', async () => {
    vi.stubGlobal('fetch', vi.fn().mockImplementation((url: string) => {
      if (url.includes('fail')) return Promise.reject(new Error('Network error'))
      return Promise.resolve({
        ok: true,
        headers: new Headers({ 'content-type': 'application/json' }),
        json: () => Promise.resolve({ data: { score: 42 } }),
      })
    }))

    const params = {
      sources: [
        { name: 'Working', url: 'https://api.working.com/check', fields: { score: 'data.score' } },
        { name: 'Failing', url: 'https://api.fail.com/check', fields: { score: 'data.score' } },
      ],
      timeout: 5,
    }

    const result = await executeEnrich(params, null, { args: {}, auth: {} })
    expect(result.length).toBe(2)
    expect(result[0]).toHaveProperty('score', 42)
    expect(result[1]).toHaveProperty('error')
  })
})
```

**Step 2: Run test to verify it fails**

Run: `npx vitest run tests/unit/enrich.test.ts`
Expected: FAIL — module not found

**Step 3: Implement enrich step**

```typescript
// src/pipeline/steps/enrich.ts
import { renderTemplate, renderObject } from '../template.js'

interface EnrichSource {
  name: string
  url: string
  method?: string
  headers?: Record<string, string>
  params?: Record<string, string>
  select?: string
  fields: Record<string, string>
}

interface EnrichParams {
  sources: EnrichSource[]
  timeout?: number
}

interface StepContext {
  args: Record<string, unknown>
  auth: Record<string, unknown>
}

export async function executeEnrich(
  params: EnrichParams,
  _data: unknown,
  ctx: StepContext,
): Promise<Record<string, unknown>[]> {
  const timeout = (params.timeout ?? 10) * 1000
  const templateCtx = { args: ctx.args, auth: ctx.auth }

  const promises = params.sources.map(async (source): Promise<Record<string, unknown>> => {
    try {
      const url = renderTemplate(source.url, templateCtx)
      const headers = (renderObject(source.headers ?? {}, templateCtx) ?? {}) as Record<string, string>
      const queryParams = (renderObject(source.params ?? {}, templateCtx) ?? {}) as Record<string, string>

      const fullUrl = new URL(url)
      for (const [k, v] of Object.entries(queryParams)) {
        if (v) fullUrl.searchParams.set(k, String(v))
      }

      const response = await fetch(fullUrl.toString(), {
        method: (source.method ?? 'GET').toUpperCase(),
        headers: { Accept: 'application/json', ...headers },
        signal: AbortSignal.timeout(timeout),
      })

      if (!response.ok) {
        return { source: source.name, status: 'error', error: `HTTP ${response.status}` }
      }

      let data = await response.json()

      // Select nested path if specified
      if (source.select) {
        data = walkPath(data, source.select.split('.'))
      }

      // Extract fields
      const row: Record<string, unknown> = { source: source.name, status: 'ok' }
      for (const [outputField, dataPath] of Object.entries(source.fields)) {
        row[outputField] = walkPath(data, dataPath.split('.'))
      }

      return row
    } catch (error) {
      return {
        source: source.name,
        status: 'error',
        error: (error as Error).message,
      }
    }
  })

  return Promise.all(promises)
}

function walkPath(value: unknown, segments: string[]): unknown {
  for (const segment of segments) {
    if (value === null || value === undefined) return undefined
    if (Array.isArray(value) && /^\d+$/.test(segment)) {
      value = value[parseInt(segment, 10)]
    } else if (typeof value === 'object') {
      value = (value as Record<string, unknown>)[segment]
    } else {
      return undefined
    }
  }
  return value
}
```

**Step 4: Wire into pipeline executor**

In `src/pipeline/executor.ts`, add import:

```typescript
import { executeEnrich } from './steps/enrich.js'
```

Add case in `executeStep`:

```typescript
    case 'enrich':
      return executeEnrich(params as any, data, ctx)
```

**Step 5: Run test to verify it passes**

Run: `npx vitest run tests/unit/enrich.test.ts`
Expected: 2 tests PASS

**Step 6: Commit**

```bash
git add src/pipeline/steps/enrich.ts src/pipeline/executor.ts tests/unit/enrich.test.ts
git commit -m "feat: add enrich pipeline step for multi-source parallel queries"
```

---

### Task 7: IP Enrichment TypeScript Adapter

**Why:** This is the flagship command: `opensec enrichment ip-enrich <ip>`. It's a TS adapter (not YAML) because it needs to dynamically build the enrich sources list based on which API keys the user has configured.

**Files:**
- Create: `src/adapters/_enrichment/ip-enrich.ts`
- Test: `tests/adapter/enrichment.test.ts`

**Step 1: Write the adapter test**

```typescript
// tests/adapter/enrichment.test.ts
import { describe, it, expect, vi, beforeEach } from 'vitest'

describe('enrichment/ip-enrich', () => {
  it('is registered after import', async () => {
    // Mock fetch to prevent real API calls
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true,
      headers: new Headers({ 'content-type': 'application/json' }),
      json: () => Promise.resolve({}),
    }))

    await import('../../src/adapters/_enrichment/ip-enrich.js')

    const { getRegistry } = await import('../../src/registry.js')
    const cmd = getRegistry().get('enrichment/ip-enrich')
    expect(cmd).toBeDefined()
    expect(cmd!.provider).toBe('enrichment')
    expect(cmd!.name).toBe('ip-enrich')
    expect(cmd!.strategy).toBe('FREE')  // Works with any subset of configured keys
  })
})
```

**Step 2: Implement the adapter**

```typescript
// src/adapters/_enrichment/ip-enrich.ts
import { cli, Strategy } from '../../registry.js'
import type { ExecContext } from '../../types.js'
import { loadAuth } from '../../auth/index.js'

interface SourceConfig {
  name: string
  provider: string
  url: (ip: string) => string
  headers: (key: string) => Record<string, string>
  select?: string
  fields: Record<string, string>
}

const SOURCES: SourceConfig[] = [
  {
    name: 'AbuseIPDB',
    provider: 'abuseipdb',
    url: (ip) => `https://api.abuseipdb.com/api/v2/check?ipAddress=${ip}&maxAgeInDays=90`,
    headers: (key) => ({ Key: key, Accept: 'application/json' }),
    select: 'data',
    fields: { abuse_score: 'abuseConfidenceScore', country: 'countryCode', isp: 'isp', total_reports: 'totalReports' },
  },
  {
    name: 'VirusTotal',
    provider: 'virustotal',
    url: (ip) => `https://www.virustotal.com/api/v3/ip_addresses/${ip}`,
    headers: (key) => ({ 'x-apikey': key, Accept: 'application/json' }),
    fields: { malicious: 'data.attributes.last_analysis_stats.malicious', as_owner: 'data.attributes.as_owner' },
  },
  {
    name: 'GreyNoise',
    provider: 'greynoise',
    url: (ip) => `https://api.greynoise.io/v3/community/${ip}`,
    headers: (key) => ({ key, Accept: 'application/json' }),
    fields: { classification: 'classification', noise: 'noise', riot: 'riot' },
  },
  {
    name: 'ipinfo',
    provider: 'ipinfo',
    url: (ip) => `https://ipinfo.io/${ip}/json`,
    headers: (key) => ({ Authorization: `Bearer ${key}`, Accept: 'application/json' }),
    fields: { country: 'country', org: 'org', city: 'city' },
  },
  {
    name: 'ThreatFox',
    provider: 'abuse.ch',
    url: () => 'https://threatfox-api.abuse.ch/api/v1/',
    headers: () => ({ 'Content-Type': 'application/json' }),
    fields: { threat_type: 'data.0.threat_type', malware: 'data.0.malware_printable' },
  },
]

cli({
  provider: 'enrichment',
  name: 'ip-enrich',
  description: 'Enrich IP address from multiple threat intelligence sources in parallel',
  strategy: Strategy.FREE,
  args: {
    ip: { type: 'string', required: true, help: 'IP address to enrich' },
  },
  columns: ['source', 'status', 'verdict', 'detail'],

  async func(ctx: ExecContext, args: Record<string, unknown>): Promise<unknown> {
    const ip = args.ip as string
    const timeout = 15_000

    const activeSources = SOURCES.filter(s => {
      if (s.provider === 'abuse.ch') return true  // Free, no key needed
      const creds = loadAuth(s.provider)
      return creds?.api_key != null
    })

    if (activeSources.length === 0) {
      return [{ source: '-', status: 'error', verdict: '-', detail: 'No API keys configured. Run: opensec auth add <provider> --api-key' }]
    }

    const results = await Promise.allSettled(
      activeSources.map(async (source) => {
        const creds = loadAuth(source.provider)
        const apiKey = creds?.api_key ?? ''

        const fetchOpts: RequestInit = {
          method: source.provider === 'abuse.ch' ? 'POST' : 'GET',
          headers: source.headers(apiKey as string),
          signal: AbortSignal.timeout(timeout),
        }

        if (source.provider === 'abuse.ch') {
          fetchOpts.body = JSON.stringify({ query: 'search_ioc', search_term: ip })
        }

        const response = await fetch(source.url(ip), fetchOpts)
        if (!response.ok) {
          return { source: source.name, status: 'error', verdict: '-', detail: `HTTP ${response.status}` }
        }

        const data = await response.json()
        let selected = data
        if (source.select) {
          selected = walkPath(data, source.select.split('.'))
        }

        const detail: string[] = []
        for (const [label, path] of Object.entries(source.fields)) {
          const val = walkPath(selected, path.split('.'))
          if (val !== undefined && val !== null) {
            detail.push(`${label}: ${val}`)
          }
        }

        const verdict = inferVerdict(source.name, selected, source.fields)

        return {
          source: source.name,
          status: 'ok',
          verdict,
          detail: detail.join(', ') || '-',
        }
      }),
    )

    return results.map((r, i) => {
      if (r.status === 'fulfilled') return r.value
      return {
        source: activeSources[i].name,
        status: 'error',
        verdict: '-',
        detail: (r.reason as Error).message,
      }
    })
  },
})

function inferVerdict(source: string, data: unknown, fields: Record<string, string>): string {
  if (!data) return '-'

  const get = (path: string) => walkPath(data, path.split('.'))

  switch (source) {
    case 'AbuseIPDB': {
      const score = Number(get('abuseConfidenceScore') ?? 0)
      if (score >= 80) return 'Malicious'
      if (score >= 30) return 'Suspicious'
      return 'Clean'
    }
    case 'VirusTotal': {
      const mal = Number(get('data.attributes.last_analysis_stats.malicious') ?? 0)
      if (mal >= 5) return 'Malicious'
      if (mal >= 1) return 'Suspicious'
      return 'Clean'
    }
    case 'GreyNoise': {
      const cls = get('classification')
      if (cls === 'malicious') return 'Malicious'
      if (cls === 'benign') return 'Clean'
      return String(cls ?? '-')
    }
    case 'ThreatFox': {
      const threat = get('data.0.threat_type')
      return threat ? 'Known IOC' : 'Not found'
    }
    default:
      return '-'
  }
}

function walkPath(value: unknown, segments: string[]): unknown {
  for (const segment of segments) {
    if (value === null || value === undefined) return undefined
    if (Array.isArray(value) && /^\d+$/.test(segment)) {
      value = value[parseInt(segment, 10)]
    } else if (typeof value === 'object') {
      value = (value as Record<string, unknown>)[segment]
    } else {
      return undefined
    }
  }
  return value
}
```

**Step 3: Run test**

Run: `npx vitest run tests/adapter/enrichment.test.ts`
Expected: PASS

**Step 4: Manual test**

Run: `npx tsx src/main.ts enrichment ip-enrich 8.8.8.8`
Expected: Table with at least ThreatFox row (free, no key needed). If you've configured API keys, more rows appear.

**Step 5: Commit**

```bash
git add src/adapters/_enrichment/ tests/adapter/enrichment.test.ts
git commit -m "feat: add ip-enrich multi-source enrichment adapter"
```

---

### Task 8: Stdin Pipe Support

**Why:** ProjectDiscovery ecosystem compat. `cat ips.txt | opensec enrichment ip-enrich --json`

**Files:**
- Modify: `src/cli.ts` — detect stdin pipe and feed to command
- Test: manual

**Step 1: Add stdin detection to cli.ts action handler**

In `src/cli.ts`, modify the action handler inside `registerAdapterCommands`:

```typescript
      sub.action(async (...actionArgs: unknown[]) => {
        try {
          const opts = resolveArgs(cmd, sub, actionArgs)
          const globalOpts = program.opts()
          const format = globalOpts.json ? 'json' : globalOpts.format

          if (globalOpts.timeout) {
            process.env['OPENSECCLI_TIMEOUT'] = globalOpts.timeout
          }

          // Stdin pipe support: if stdin is not TTY, read lines and run command per line
          if (!process.stdin.isTTY && requiredArgNames.length > 0 && !(requiredArgNames[0] in opts)) {
            const lines = await readStdinLines()
            for (const line of lines) {
              const lineOpts = { ...opts, [requiredArgNames[0]]: line }
              await executeCommand(`${provider}/${cmd.name}`, lineOpts, { format })
            }
            return
          }

          await executeCommand(`${provider}/${cmd.name}`, opts, { format })
        } catch (error) {
          handleError(error)
        }
      })
```

Add helper at bottom of `src/cli.ts`:

```typescript
async function readStdinLines(): Promise<string[]> {
  const chunks: Buffer[] = []
  for await (const chunk of process.stdin) {
    chunks.push(chunk)
  }
  return Buffer.concat(chunks)
    .toString('utf-8')
    .split('\n')
    .map(l => l.trim())
    .filter(l => l.length > 0)
}
```

**Step 2: Manual test**

Run: `echo "CVE-2024-3094" | npx tsx src/main.ts nvd cve-get --json 2>/dev/null | python3 -m json.tool | head -5`
Expected: JSON output for CVE-2024-3094

**Step 3: Commit**

```bash
git add src/cli.ts
git commit -m "feat: add stdin pipe support for ProjectDiscovery ecosystem compat"
```

---

### Task 9: Run All Tests + Final Verification

**Step 1: Run full test suite**

Run: `npx vitest run`
Expected: All unit + adapter tests PASS

**Step 2: Verify adapter count**

Run: `npx tsx src/main.ts list --json 2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); print(f'{len(d)} adapters loaded')"`
Expected: `15 adapters loaded` (8 Phase 0 + 1 AbuseIPDB + 3 VT + 1 GreyNoise + 1 ipinfo + 1 Shodan = 15, minus ThreatFox is already counted, plus enrichment/ip-enrich = depends on discovery)

**Step 3: Run doctor**

Run: `npx tsx src/main.ts doctor`
Expected: Shows version, node, adapter count, auth count

**Step 4: Commit final state**

```bash
git add -A
git commit -m "chore: phase 1 complete — 15+ adapters, enrich, auth test, stdin pipe"
```

---

## Summary

| Task | What | Files | Tests |
|------|------|-------|-------|
| 1 | Template engine tests + deep path fix | template.ts | 8 unit tests |
| 2 | Auth test command | auth/test.ts, cli.ts | 5 unit tests |
| 3 | AbuseIPDB adapter | abuseipdb/ip-check.yaml | 1 adapter test |
| 4 | VirusTotal adapters (3) | virustotal/*.yaml | 1 adapter test |
| 5 | GreyNoise + ipinfo + Shodan | 3 YAML adapters | verify via list |
| 6 | Enrich pipeline step | pipeline/steps/enrich.ts | 2 unit tests |
| 7 | IP enrichment adapter | _enrichment/ip-enrich.ts | 1 adapter test |
| 8 | Stdin pipe support | cli.ts | manual |
| 9 | Full verification | - | all tests |

**Total: 9 tasks, ~9 commits, 6 new YAML adapters, 1 TS adapter, 1 new pipeline step, ~18 tests**
