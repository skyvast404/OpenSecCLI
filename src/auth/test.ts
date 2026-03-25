/**
 * Auth test module — validates API keys by hitting lightweight endpoints.
 */

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
