import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import {
  collectEvidence,
  loadEvidence,
  buildComplianceReport,
  FRAMEWORK_CONTROLS,
  SUPPORTED_FRAMEWORKS,
} from '../../src/commands/compliance.js'
import type { ComplianceEvidence } from '../../src/commands/compliance.js'
import { writeFile, rm, mkdir } from 'node:fs/promises'
import { join } from 'node:path'
import { tmpdir } from 'node:os'

describe('compliance', () => {
  describe('FRAMEWORK_CONTROLS', () => {
    it('supports owasp, pci-dss, soc2, and cis-docker frameworks', () => {
      expect(SUPPORTED_FRAMEWORKS).toContain('owasp')
      expect(SUPPORTED_FRAMEWORKS).toContain('pci-dss')
      expect(SUPPORTED_FRAMEWORKS).toContain('soc2')
      expect(SUPPORTED_FRAMEWORKS).toContain('cis-docker')
    })

    it('owasp has A01 through A10 controls', () => {
      const owasp = FRAMEWORK_CONTROLS['owasp']
      expect(owasp.length).toBe(10)
      expect(owasp[0].control_id).toBe('A01')
      expect(owasp[9].control_id).toBe('A10')
    })

    it('each control has required fields and a check function', () => {
      for (const [framework, controls] of Object.entries(FRAMEWORK_CONTROLS)) {
        for (const control of controls) {
          expect(control.control_id, `${framework}/${control.control_id}`).toBeTruthy()
          expect(control.control_name, `${framework}/${control.control_id}`).toBeTruthy()
          expect(control.commands.length, `${framework}/${control.control_id}`).toBeGreaterThan(0)
          expect(typeof control.check).toBe('function')
        }
      }
    })

    it('check functions return valid statuses', () => {
      const validStatuses = ['pass', 'fail', 'partial', 'not_tested']
      for (const controls of Object.values(FRAMEWORK_CONTROLS)) {
        for (const control of controls) {
          // Test with empty results
          const status = control.check([])
          expect(validStatuses).toContain(status)

          // Test with vulnerable results
          const vulnStatus = control.check([{ vulnerable: true, severity: 'critical' }])
          expect(validStatuses).toContain(vulnStatus)
        }
      }
    })
  })

  describe('collectEvidence', () => {
    it('collects evidence for owasp framework', async () => {
      const evidence = await collectEvidence('owasp', '.')
      expect(evidence.framework).toBe('owasp')
      expect(evidence.controls.length).toBe(10)
      expect(evidence.collected_at).toBeTruthy()
      expect(evidence.summary.total).toBe(10)
      expect(evidence.summary.pass + evidence.summary.fail +
        evidence.summary.partial + evidence.summary.not_tested).toBe(10)
    })

    it('throws for unsupported framework', async () => {
      await expect(collectEvidence('iso27001', '.')).rejects.toThrow('Unsupported framework')
    })

    it('produces evidence with timestamps for each control', async () => {
      const evidence = await collectEvidence('soc2', '.')
      for (const control of evidence.controls) {
        expect(control.timestamp).toBeTruthy()
        expect(control.evidence_summary).toBeTruthy()
      }
    })

    it('summary counts match controls array', async () => {
      const evidence = await collectEvidence('pci-dss', '.')
      const { summary, controls } = evidence
      const passCount = controls.filter(c => c.status === 'pass').length
      const failCount = controls.filter(c => c.status === 'fail').length
      const partialCount = controls.filter(c => c.status === 'partial').length
      const notTestedCount = controls.filter(c => c.status === 'not_tested').length
      expect(summary.pass).toBe(passCount)
      expect(summary.fail).toBe(failCount)
      expect(summary.partial).toBe(partialCount)
      expect(summary.not_tested).toBe(notTestedCount)
    })
  })

  describe('loadEvidence', () => {
    const tmpDir = join(tmpdir(), 'opensec-compliance-test-' + Date.now())

    beforeEach(async () => {
      await mkdir(tmpDir, { recursive: true })
    })

    afterEach(async () => {
      await rm(tmpDir, { recursive: true, force: true })
    })

    it('loads valid evidence JSON', async () => {
      const evidence: ComplianceEvidence = {
        framework: 'owasp',
        collected_at: '2026-01-01T00:00:00.000Z',
        controls: [
          {
            control_id: 'A01',
            control_name: 'Broken Access Control',
            status: 'pass',
            commands_run: ['vuln/cors-check'],
            results_count: 0,
            evidence_summary: 'No issues found',
            timestamp: '2026-01-01T00:00:00.000Z',
          },
        ],
        summary: { total: 1, pass: 1, fail: 0, partial: 0, not_tested: 0 },
      }

      const filePath = join(tmpDir, 'evidence.json')
      await writeFile(filePath, JSON.stringify(evidence), 'utf-8')

      const loaded = await loadEvidence(filePath)
      expect(loaded.framework).toBe('owasp')
      expect(loaded.controls).toHaveLength(1)
      expect(loaded.controls[0].control_id).toBe('A01')
    })

    it('throws for invalid JSON', async () => {
      const filePath = join(tmpDir, 'bad.json')
      await writeFile(filePath, 'not valid json', 'utf-8')
      await expect(loadEvidence(filePath)).rejects.toThrow('Failed to parse')
    })
  })

  describe('buildComplianceReport', () => {
    it('converts evidence to table rows', () => {
      const evidence: ComplianceEvidence = {
        framework: 'soc2',
        collected_at: '2026-01-01T00:00:00.000Z',
        controls: [
          {
            control_id: 'CC6.1',
            control_name: 'Logical Access Controls',
            status: 'pass',
            commands_run: ['vuln/cors-check', 'vuln/cookie-analyzer'],
            results_count: 5,
            evidence_summary: 'Checked via vuln/cors-check, vuln/cookie-analyzer',
            timestamp: '2026-01-01T00:00:00.000Z',
          },
          {
            control_id: 'CC6.6',
            control_name: 'System Boundary',
            status: 'fail',
            commands_run: ['vuln/header-audit'],
            results_count: 3,
            evidence_summary: 'Issues detected',
            timestamp: '2026-01-01T00:00:00.000Z',
          },
        ],
        summary: { total: 2, pass: 1, fail: 1, partial: 0, not_tested: 0 },
      }

      const rows = buildComplianceReport(evidence)
      expect(rows).toHaveLength(2)
      expect(rows[0]).toMatchObject({
        control_id: 'CC6.1',
        status: 'pass',
        commands_run: 'vuln/cors-check, vuln/cookie-analyzer',
      })
      expect(rows[1]).toMatchObject({
        control_id: 'CC6.6',
        status: 'fail',
      })
    })

    it('shows "none" for controls with no commands run', () => {
      const evidence: ComplianceEvidence = {
        framework: 'owasp',
        collected_at: '2026-01-01T00:00:00.000Z',
        controls: [
          {
            control_id: 'A01',
            control_name: 'Test',
            status: 'not_tested',
            commands_run: [],
            results_count: 0,
            evidence_summary: 'No commands',
            timestamp: '2026-01-01T00:00:00.000Z',
          },
        ],
        summary: { total: 1, pass: 0, fail: 0, partial: 0, not_tested: 1 },
      }

      const rows = buildComplianceReport(evidence)
      expect(rows[0].commands_run).toBe('none')
    })
  })
})
