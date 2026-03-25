import { describe, it, expect } from 'vitest'
import {
  parseSubfinderOutput,
  parseHttpxOutput,
  parseNmapOutput,
  parseFfufOutput,
} from '../../src/adapters/recon/parsers.js'

describe('recon parsers', () => {
  describe('parseSubfinderOutput', () => {
    it('parses JSONL output from subfinder', () => {
      const input = '{"host":"api.example.com","source":"crtsh"}\n{"host":"mail.example.com","source":"dnsdumpster"}\n'
      const result = parseSubfinderOutput(input)
      expect(result).toEqual([
        { subdomain: 'api.example.com', source: 'crtsh' },
        { subdomain: 'mail.example.com', source: 'dnsdumpster' },
      ])
    })

    it('handles plain text output (amass fallback)', () => {
      const input = 'api.example.com\nmail.example.com\n'
      const result = parseSubfinderOutput(input)
      expect(result).toEqual([
        { subdomain: 'api.example.com', source: 'amass' },
        { subdomain: 'mail.example.com', source: 'amass' },
      ])
    })
  })

  describe('parseHttpxOutput', () => {
    it('parses JSONL output from httpx', () => {
      const input = JSON.stringify({
        url: 'https://example.com',
        status_code: 200,
        title: 'Example',
        tech: ['nginx', 'React'],
        content_length: 12345,
        webserver: 'nginx/1.24',
      }) + '\n'
      const result = parseHttpxOutput(input)
      expect(result).toHaveLength(1)
      expect(result[0]).toMatchObject({
        url: 'https://example.com',
        status: 200,
        title: 'Example',
        technologies: 'nginx, React',
        server: 'nginx/1.24',
      })
    })
  })

  describe('parseNmapOutput', () => {
    it('parses nmap XML output', () => {
      const xml = `<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="93.184.216.34" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx" version="1.24"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="https" product="nginx" version="1.24"/>
      </port>
    </ports>
  </host>
</nmaprun>`
      const result = parseNmapOutput(xml)
      expect(result).toHaveLength(2)
      expect(result[0]).toMatchObject({
        ip: '93.184.216.34',
        port: 80,
        protocol: 'tcp',
        state: 'open',
        service: 'http',
        product: 'nginx',
        version: '1.24',
      })
    })
  })

  describe('parseFfufOutput', () => {
    it('parses ffuf JSON output', () => {
      const output = JSON.stringify({
        results: [
          { url: 'https://example.com/admin', status: 200, length: 1234, words: 100 },
          { url: 'https://example.com/api', status: 301, length: 0, words: 0 },
        ],
      })
      const result = parseFfufOutput(output)
      expect(result).toHaveLength(2)
      expect(result[0]).toMatchObject({
        url: 'https://example.com/admin',
        status: 200,
        length: 1234,
      })
    })
  })
})
