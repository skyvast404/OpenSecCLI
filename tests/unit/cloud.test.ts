import { describe, it, expect } from 'vitest'
import {
  parseCheckovOutput,
  parseTerrascanOutput,
} from '../../src/adapters/cloud/iac-scan.js'
import {
  parseTrivyOutput,
  parseGrypeOutput,
} from '../../src/adapters/cloud/container-scan.js'
import {
  parseKubeBenchOutput,
  parseKubeHunterOutput,
} from '../../src/adapters/cloud/kube-audit.js'

describe('cloud/iac-scan', () => {
  it('parses checkov JSON output', () => {
    const input = JSON.stringify({
      results: {
        failed_checks: [
          {
            check_id: 'CKV_AWS_1',
            resource: 'aws_s3_bucket.example',
            check_result: { result: 'FAILED' },
            severity: 'HIGH',
            guideline: 'Ensure S3 bucket has encryption enabled',
            file_path: '/main.tf',
          },
        ],
      },
    })

    const rows = parseCheckovOutput(input)
    expect(rows).toHaveLength(1)
    expect(rows[0]).toEqual({
      check_id: 'CKV_AWS_1',
      resource: 'aws_s3_bucket.example',
      severity: 'HIGH',
      status: 'FAILED',
      detail: 'Ensure S3 bucket has encryption enabled',
      file: '/main.tf',
    })
  })

  it('returns empty array on invalid input', () => {
    expect(parseCheckovOutput('not json')).toEqual([])
  })

  it('parses terrascan JSON output', () => {
    const input = JSON.stringify({
      results: {
        violations: [
          {
            rule_id: 'AC_AWS_001',
            resource_name: 'my_bucket',
            severity: 'HIGH',
            description: 'S3 bucket is public',
            file: 'main.tf',
          },
        ],
      },
    })

    const rows = parseTerrascanOutput(input)
    expect(rows).toHaveLength(1)
    expect(rows[0]).toMatchObject({
      check_id: 'AC_AWS_001',
      resource: 'my_bucket',
      severity: 'HIGH',
      status: 'FAILED',
    })
  })
})

describe('cloud/container-scan', () => {
  it('parses trivy JSON output', () => {
    const input = JSON.stringify({
      Results: [
        {
          Vulnerabilities: [
            {
              PkgName: 'openssl',
              InstalledVersion: '1.1.1k',
              VulnerabilityID: 'CVE-2022-0778',
              Severity: 'HIGH',
              FixedVersion: '1.1.1n',
            },
          ],
        },
      ],
    })

    const rows = parseTrivyOutput(input)
    expect(rows).toHaveLength(1)
    expect(rows[0]).toEqual({
      package: 'openssl',
      version: '1.1.1k',
      vulnerability: 'CVE-2022-0778',
      severity: 'HIGH',
      fixed_version: '1.1.1n',
    })
  })

  it('parses grype JSON output', () => {
    const input = JSON.stringify({
      matches: [
        {
          artifact: { name: 'curl', version: '7.68.0' },
          vulnerability: {
            id: 'CVE-2023-1234',
            severity: 'Critical',
            fix: { versions: ['7.88.0'] },
          },
        },
      ],
    })

    const rows = parseGrypeOutput(input)
    expect(rows).toHaveLength(1)
    expect(rows[0]).toMatchObject({
      package: 'curl',
      vulnerability: 'CVE-2023-1234',
      fixed_version: '7.88.0',
    })
  })
})

describe('cloud/kube-audit', () => {
  it('parses kube-bench JSON output, filtering FAIL and WARN', () => {
    const input = JSON.stringify({
      Controls: [
        {
          tests: [
            {
              results: [
                {
                  test_number: '1.1.1',
                  test_desc: 'Ensure API server is not anonymous',
                  status: 'FAIL',
                  remediation: 'Set --anonymous-auth=false',
                },
                {
                  test_number: '1.1.2',
                  test_desc: 'Ensure audit logging is enabled',
                  status: 'PASS',
                },
                {
                  test_number: '1.1.3',
                  test_desc: 'Check kubelet certificate',
                  status: 'WARN',
                  severity: 'LOW',
                },
              ],
            },
          ],
        },
      ],
    })

    const rows = parseKubeBenchOutput(input)
    expect(rows).toHaveLength(2)
    expect(rows[0]).toMatchObject({ id: '1.1.1', status: 'FAIL' })
    expect(rows[1]).toMatchObject({ id: '1.1.3', status: 'WARN', severity: 'LOW' })
  })

  it('parses kube-hunter JSON output', () => {
    const input = JSON.stringify({
      vulnerabilities: [
        {
          vid: 'KHV001',
          description: 'Unauthenticated access to API',
          severity: 'high',
        },
      ],
    })

    const rows = parseKubeHunterOutput(input)
    expect(rows).toHaveLength(1)
    expect(rows[0]).toMatchObject({
      id: 'KHV001',
      status: 'FAIL',
      severity: 'HIGH',
    })
  })
})
