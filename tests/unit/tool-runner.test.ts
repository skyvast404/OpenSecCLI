import { describe, it, expect } from 'vitest'
import { checkToolInstalled, parseJsonLines } from '../../src/adapters/_utils/tool-runner.js'

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
})
