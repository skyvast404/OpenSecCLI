import { describe, it, expect } from 'vitest'
import {
  detectLanguages,
  detectFrameworks,
  buildProjectMap,
} from '../../src/adapters/scan/discover.js'

describe('detectLanguages', () => {
  it('detects from file extensions', () => {
    const files = ['src/app.py', 'src/utils.py', 'lib/helper.js', 'README.md']
    const langs = detectLanguages(files)
    expect(langs).toContain('python')
    expect(langs).toContain('javascript')
    expect(langs).not.toContain('markdown')
  })
})

describe('detectFrameworks', () => {
  it('detects Flask from imports', () => {
    const contents = new Map([
      ['app.py', 'from flask import Flask\napp = Flask(__name__)'],
    ])
    const frameworks = detectFrameworks(contents)
    expect(frameworks).toContain('flask')
  })

  it('detects Express from require', () => {
    const contents = new Map([
      ['server.js', "const express = require('express')\nconst app = express()"],
    ])
    const frameworks = detectFrameworks(contents)
    expect(frameworks).toContain('express')
  })

  it('detects multiple frameworks', () => {
    const contents = new Map([
      ['app.py', 'from fastapi import FastAPI'],
      ['server.js', "import express from 'express'"],
    ])
    const frameworks = detectFrameworks(contents)
    expect(frameworks).toContain('fastapi')
    expect(frameworks).toContain('express')
  })
})

describe('buildProjectMap', () => {
  it('assembles all discovery data', () => {
    const map = buildProjectMap({
      path: '/repo',
      languages: ['python'],
      frameworks: ['flask'],
      entryPoints: [{ file: 'app.py', line: 10, kind: 'http_route' as const }],
      gitSignals: [{ commit: 'abc', message: 'fix: xss', files: ['a.py'] }],
      sourceFiles: ['app.py', 'utils.py'],
    })
    expect(map.path).toBe('/repo')
    expect(map.languages).toEqual(['python'])
    expect(map.entry_points).toHaveLength(1)
    expect(map.git_security_signals).toHaveLength(1)
  })
})
