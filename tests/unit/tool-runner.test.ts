import { describe, it, expect } from 'vitest'
import { checkToolInstalled, parseJsonLines, getToolVersion, runExternalTool } from '../../src/adapters/_utils/tool-runner.js'
import { ToolNotFoundError } from '../../src/errors.js'

describe('tool-runner', () => {
  describe('parseJsonLines', () => {
    it('parses newline-delimited JSON', () => {
      const input = '{"host":"a.com"}\n{"host":"b.com"}\n'
      const result = parseJsonLines(input)
      expect(result).toEqual([{ host: 'a.com' }, { host: 'b.com' }])
    })

    it('skips empty lines and non-JSON lines', () => {
      const input = '{"host":"a.com"}\n\n[info] starting\n{"host":"b.com"}'
      const result = parseJsonLines(input)
      expect(result).toEqual([{ host: 'a.com' }, { host: 'b.com' }])
    })
  })

  describe('checkToolInstalled', () => {
    it('returns true when tool exists', async () => {
      const result = await checkToolInstalled('node')
      expect(result).toBe(true)
    })

    it('returns false when tool missing', async () => {
      const result = await checkToolInstalled('nonexistent_tool_xyz_12345')
      expect(result).toBe(false)
    })
  })

  describe('runExternalTool', () => {
    it('throws ToolNotFoundError when no tools available', async () => {
      await expect(
        runExternalTool({
          tools: ['nonexistent_tool_xyz_99999'],
          buildArgs: () => [],
          parseOutput: () => [],
        }),
      ).rejects.toBeInstanceOf(ToolNotFoundError)
    })

    it('includes installHint in error when provided', async () => {
      try {
        await runExternalTool({
          tools: ['nonexistent_tool_xyz_99999'],
          buildArgs: () => [],
          parseOutput: () => [],
          installHint: 'brew install mytool',
        })
      } catch (e) {
        expect(e).toBeInstanceOf(ToolNotFoundError)
        expect((e as ToolNotFoundError).hint).toContain('brew install mytool')
      }
    })
  })

  describe('getToolVersion', () => {
    it('returns version string for installed tool', async () => {
      const version = await getToolVersion('node')
      expect(version).toMatch(/^\d+\.\d+/)
    })

    it('returns null for missing tool', async () => {
      const version = await getToolVersion('nonexistent_tool_xyz_99999')
      expect(version).toBeNull()
    })
  })
})
