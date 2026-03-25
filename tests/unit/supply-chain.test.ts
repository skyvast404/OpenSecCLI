import { describe, it, expect } from 'vitest'
import { parseCiAuditFindings } from '../../src/adapters/supply-chain/ci-audit.js'

describe('supply-chain', () => {
  describe('ci-audit', () => {
    it('detects unpinned GitHub Actions', () => {
      const yaml = `
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: some-action/setup@main
      - uses: actions/upload-artifact@v3
`
      const result = parseCiAuditFindings('.github/workflows/ci.yml', yaml)
      const unpinned = result.filter((r) => r.rule === 'unpinned-action')
      expect(unpinned.length).toBeGreaterThanOrEqual(1)
      // 'main' is not a version tag or SHA, so it should be flagged
      const mainRef = unpinned.find((r) => r.detail.includes('some-action/setup@main'))
      expect(mainRef).toBeDefined()
    })

    it('does not flag SHA-pinned or version-tagged actions', () => {
      const yaml = `
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29
      - uses: actions/setup-node@v4
`
      const result = parseCiAuditFindings('.github/workflows/ci.yml', yaml)
      const unpinned = result.filter((r) => r.rule === 'unpinned-action')
      expect(unpinned).toHaveLength(0)
    })

    it('detects expression injection in run steps', () => {
      const yaml = `
name: PR
on: pull_request
jobs:
  greet:
    runs-on: ubuntu-latest
    steps:
      - run: echo "Hello \${{ github.event.pull_request.title }}"
`
      const result = parseCiAuditFindings('.github/workflows/pr.yml', yaml)
      const injection = result.filter((r) => r.rule === 'expression-injection')
      expect(injection.length).toBeGreaterThanOrEqual(1)
      expect(injection[0].severity).toBe('critical')
    })

    it('detects secrets leaked in echo', () => {
      const yaml = `
name: Deploy
on: push
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - run: echo \${{ secrets.API_KEY }}
`
      const result = parseCiAuditFindings('.github/workflows/deploy.yml', yaml)
      const secretLogs = result.filter((r) => r.rule === 'secret-in-log')
      expect(secretLogs.length).toBeGreaterThanOrEqual(1)
      expect(secretLogs[0].severity).toBe('high')
    })

    it('detects pull_request_target with PR head checkout', () => {
      const yaml = `
name: PR Target
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: \${{ github.event.pull_request.head.sha }}
`
      const result = parseCiAuditFindings('.github/workflows/prt.yml', yaml)
      const prt = result.filter((r) => r.rule === 'prt-checkout')
      expect(prt.length).toBeGreaterThanOrEqual(1)
      expect(prt[0].severity).toBe('critical')
    })

    it('returns empty array for safe workflows', () => {
      const yaml = `
name: Safe
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29
      - run: npm test
`
      const result = parseCiAuditFindings('.github/workflows/safe.yml', yaml)
      expect(result).toHaveLength(0)
    })
  })
})
