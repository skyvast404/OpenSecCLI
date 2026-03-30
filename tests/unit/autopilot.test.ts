import { describe, it, expect } from 'vitest'
import { detectTargetType } from '../../src/commands/autopilot.js'

describe('detectTargetType', () => {
  it('detects HTTP URLs', () => {
    expect(detectTargetType('http://example.com')).toBe('url')
  })

  it('detects HTTPS URLs', () => {
    expect(detectTargetType('https://example.com/path?q=1')).toBe('url')
  })

  it('detects bare domain names as URL targets', () => {
    expect(detectTargetType('example.com')).toBe('url')
    expect(detectTargetType('sub.domain.example.co.uk')).toBe('url')
  })

  it('detects relative file paths as path targets', () => {
    expect(detectTargetType('./myproject')).toBe('path')
    expect(detectTargetType('../other')).toBe('path')
  })

  it('detects absolute file paths as path targets', () => {
    expect(detectTargetType('/home/user/project')).toBe('path')
    expect(detectTargetType('/var/www/app')).toBe('path')
  })

  it('detects dot (current directory) as path target', () => {
    expect(detectTargetType('.')).toBe('path')
  })

  it('detects other protocol schemes as URL targets', () => {
    expect(detectTargetType('ftp://files.example.com')).toBe('url')
  })

  it('detects plain directory names as path targets', () => {
    expect(detectTargetType('myproject')).toBe('path')
    expect(detectTargetType('src')).toBe('path')
  })

  it('detects domain with path as URL target', () => {
    expect(detectTargetType('example.com/api/v1')).toBe('url')
  })

  it('detects URLs with ports', () => {
    expect(detectTargetType('https://localhost:3000')).toBe('url')
  })
})
