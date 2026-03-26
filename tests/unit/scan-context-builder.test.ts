import { describe, it, expect } from 'vitest'
import {
  countSinkHits,
  computeNameBonus,
  parseImportSpecifiers,
  SINK_KEYWORDS,
} from '../../src/adapters/scan/context-builder.js'

describe('countSinkHits', () => {
  it('counts occurrences of sink keywords in content', () => {
    const content = `
      db.query("SELECT * FROM users WHERE id = " + userId)
      cursor.execute(sql)
      os.system("rm -rf /")
    `
    const hits = countSinkHits(content)
    // 'query' x1, 'exec' inside execute x1, 'execute' x1, 'system' x1 = 4
    expect(hits).toBe(4)
  })

  it('counts multiple occurrences of the same keyword', () => {
    const content = `
      eval(userInput)
      eval(anotherInput)
      eval(thirdInput)
    `
    const hits = countSinkHits(content)
    expect(hits).toBe(3)
  })

  it('returns 0 for content with no sink keywords', () => {
    const content = `
      function add(a, b) {
        return a + b
      }
      const x = 42
    `
    const hits = countSinkHits(content)
    expect(hits).toBe(0)
  })

  it('matches case-insensitively', () => {
    const content = 'innerHTML = "<div>"; document.write("hi"); EVAL(x)'
    const hits = countSinkHits(content)
    // innerHTML x1, document.write x1, eval x1 = 3
    expect(hits).toBe(3)
  })

  it('detects all 22 defined sink keywords', () => {
    expect(SINK_KEYWORDS.length).toBe(22)

    // Use unique delimiters so no keyword is a substring of another entry
    const content = SINK_KEYWORDS.join(' ||| ')
    const hits = countSinkHits(content)
    // At minimum each keyword counted once; some overlap is expected
    // (e.g., 'exec' appears inside 'execute')
    expect(hits).toBeGreaterThanOrEqual(22)
  })
})

describe('computeNameBonus', () => {
  it('scores security-related filenames higher', () => {
    expect(computeNameBonus('src/auth/login.ts')).toBeGreaterThan(0)
    expect(computeNameBonus('src/db/connection.ts')).toBeGreaterThan(0)
    expect(computeNameBonus('src/models/user.ts')).toBeGreaterThan(0)
  })

  it('returns 0 for non-security filenames', () => {
    expect(computeNameBonus('src/utils/format.ts')).toBe(0)
    expect(computeNameBonus('src/components/button.tsx')).toBe(0)
  })

  it('stacks bonuses for multiple keyword matches', () => {
    const singleBonus = computeNameBonus('src/auth/handler.ts')
    const doubleBonus = computeNameBonus('src/auth/user-service.ts')
    // 'auth' + 'user' + 'service' = 15 vs 'auth' = 5
    expect(doubleBonus).toBeGreaterThan(singleBonus)
  })
})

describe('parseImportSpecifiers', () => {
  it('parses ES module imports', () => {
    const content = `
      import { readFile } from 'node:fs'
      import express from 'express'
      import { handler } from './handler'
    `
    const specifiers = parseImportSpecifiers(content)
    expect(specifiers).toContain('node:fs')
    expect(specifiers).toContain('express')
    expect(specifiers).toContain('./handler')
  })

  it('parses CommonJS require calls', () => {
    const content = `
      const fs = require('fs')
      const db = require('./db')
      const auth = require('./auth/index')
    `
    const specifiers = parseImportSpecifiers(content)
    expect(specifiers).toContain('fs')
    expect(specifiers).toContain('./db')
    expect(specifiers).toContain('./auth/index')
  })

  it('parses Python from-import statements', () => {
    const content = `
      from flask import Flask
      from models import User
      from utils.helpers import sanitize
    `
    const specifiers = parseImportSpecifiers(content)
    expect(specifiers).toContain('flask')
    expect(specifiers).toContain('models')
    expect(specifiers).toContain('utils.helpers')
  })

  it('deduplicates repeated imports', () => {
    const content = `
      import { a } from './shared'
      import { b } from './shared'
    `
    const specifiers = parseImportSpecifiers(content)
    const sharedHits = specifiers.filter(s => s === './shared')
    expect(sharedHits).toHaveLength(1)
  })
})
