import { describe, it, expect } from 'vitest'
import { parseSnykTestOutput, parseSnykIacOutput } from '../../src/adapters/supply-chain/snyk-scan.js'
import { parseArjunOutput } from '../../src/adapters/recon/param-discover.js'
import { parseHarvesterOutput } from '../../src/adapters/recon/osint-harvest.js'

describe('snyk-scan', () => {
  it('parses Snyk test JSON with vulnerabilities', () => {
    const raw = JSON.stringify({
      vulnerabilities: [
        {
          packageName: 'lodash',
          version: '4.17.15',
          severity: 'high',
          title: 'Prototype Pollution',
          fixedIn: ['4.17.21'],
          exploit: 'Proof of Concept',
        },
        {
          packageName: 'express',
          version: '4.17.1',
          severity: 'medium',
          title: 'Open Redirect',
          fixedIn: [],
          exploit: 'No Known Exploit',
        },
      ],
    })

    const result = parseSnykTestOutput(raw)
    expect(result).toHaveLength(2)
    expect(result[0]).toEqual({
      package: 'lodash',
      version: '4.17.15',
      severity: 'high',
      vulnerability: 'Prototype Pollution',
      fix_version: '4.17.21',
      exploit_maturity: 'Proof of Concept',
    })
    expect(result[1]).toMatchObject({
      package: 'express',
      fix_version: 'N/A',
    })
  })

  it('returns empty array when no vulnerabilities', () => {
    const raw = JSON.stringify({ ok: true })
    const result = parseSnykTestOutput(raw)
    expect(result).toEqual([])
  })

  it('handles missing optional fields gracefully', () => {
    const raw = JSON.stringify({
      vulnerabilities: [{ packageName: 'minimist' }],
    })
    const result = parseSnykTestOutput(raw)
    expect(result).toHaveLength(1)
    expect(result[0]).toEqual({
      package: 'minimist',
      version: '',
      severity: 'medium',
      vulnerability: '',
      fix_version: 'N/A',
      exploit_maturity: 'unknown',
    })
  })

  it('parses Snyk IaC JSON output', () => {
    const raw = JSON.stringify({
      infrastructureAsCodeIssues: [
        {
          id: 'SNYK-CC-TF-1',
          severity: 'high',
          title: 'S3 bucket without encryption',
          resolve: 'Enable server-side encryption',
          path: ['resource', 'aws_s3_bucket', 'main'],
        },
        {
          id: 'SNYK-CC-TF-2',
          severity: 'low',
          title: 'Security group allows ingress from 0.0.0.0',
          resolve: 'Restrict CIDR range',
          path: ['resource', 'aws_security_group'],
        },
      ],
    })

    const result = parseSnykIacOutput(raw)
    expect(result).toHaveLength(2)
    expect(result[0]).toEqual({
      package: 'SNYK-CC-TF-1',
      version: '',
      severity: 'high',
      vulnerability: 'S3 bucket without encryption',
      fix_version: 'Enable server-side encryption',
      exploit_maturity: 'resource > aws_s3_bucket > main',
    })
    expect(result[1]).toMatchObject({
      severity: 'low',
      exploit_maturity: 'resource > aws_security_group',
    })
  })

  it('returns empty array for IaC with no issues', () => {
    const raw = JSON.stringify({ ok: true })
    const result = parseSnykIacOutput(raw)
    expect(result).toEqual([])
  })
})

describe('param-discover (arjun)', () => {
  it('parses Arjun JSON output with multiple params', () => {
    const raw = JSON.stringify({
      'https://target.com/search': {
        GET: ['q', 'page', 'debug'],
      },
    })

    const result = parseArjunOutput(raw)
    expect(result).toHaveLength(3)
    expect(result[0]).toEqual({
      url: 'https://target.com/search',
      method: 'GET',
      parameter: 'q',
      source: 'arjun',
    })
    expect(result[2]).toMatchObject({
      parameter: 'debug',
      method: 'GET',
    })
  })

  it('parses multiple URLs and methods', () => {
    const raw = JSON.stringify({
      'https://target.com/api': {
        POST: ['username', 'password'],
      },
      'https://target.com/search': {
        GET: ['q'],
      },
    })

    const result = parseArjunOutput(raw)
    expect(result).toHaveLength(3)

    const postParams = result.filter((r) => r.method === 'POST')
    expect(postParams).toHaveLength(2)

    const getParams = result.filter((r) => r.method === 'GET')
    expect(getParams).toHaveLength(1)
  })

  it('returns empty array when no params discovered', () => {
    const raw = JSON.stringify({})
    const result = parseArjunOutput(raw)
    expect(result).toEqual([])
  })
})

describe('osint-harvest (theHarvester)', () => {
  it('parses theHarvester JSON with all result types', () => {
    const raw = JSON.stringify({
      emails: ['admin@example.com', 'user@example.com'],
      hosts: ['mail.example.com:1.2.3.4', 'www.example.com:5.6.7.8'],
      ips: ['1.2.3.4', '5.6.7.8'],
      asns: ['AS12345'],
    })

    const result = parseHarvesterOutput(raw)
    expect(result).toHaveLength(7)

    const emails = result.filter((r) => r.type === 'email')
    expect(emails).toHaveLength(2)
    expect(emails[0]).toEqual({
      type: 'email',
      value: 'admin@example.com',
      source: 'theHarvester',
    })

    const hosts = result.filter((r) => r.type === 'host')
    expect(hosts).toHaveLength(2)

    const ips = result.filter((r) => r.type === 'ip')
    expect(ips).toHaveLength(2)

    const asns = result.filter((r) => r.type === 'asn')
    expect(asns).toHaveLength(1)
    expect(asns[0]).toMatchObject({ value: 'AS12345' })
  })

  it('handles partial data (only emails)', () => {
    const raw = JSON.stringify({
      emails: ['info@example.com'],
    })

    const result = parseHarvesterOutput(raw)
    expect(result).toHaveLength(1)
    expect(result[0]).toEqual({
      type: 'email',
      value: 'info@example.com',
      source: 'theHarvester',
    })
  })

  it('returns empty array for empty harvester output', () => {
    const raw = JSON.stringify({
      emails: [],
      hosts: [],
      ips: [],
      asns: [],
    })

    const result = parseHarvesterOutput(raw)
    expect(result).toEqual([])
  })
})
