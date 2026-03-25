/**
 * Shared constants for OpenSecCLI.
 * Mirrors OpenCLI's constants.ts — adapted for security domain.
 */

export const DEFAULT_COMMAND_TIMEOUT = 60
export const DEFAULT_ENRICH_TIMEOUT = 30
export const CONFIG_DIR_NAME = '.openseccli'

/** Standard field role mapping for security data normalization */
export const FIELD_ROLES: Record<string, string[]> = {
  ip: ['ip', 'ipAddress', 'ip_address', 'src_ip', 'dest_ip', 'host', 'address'],
  domain: ['domain', 'hostname', 'host', 'fqdn', 'dns_name'],
  hash: ['hash', 'md5', 'sha1', 'sha256', 'sha512', 'file_hash', 'sample_hash'],
  url: ['url', 'uri', 'link', 'href', 'malware_url', 'phishing_url'],
  cve: ['cve', 'cve_id', 'cveId', 'vulnerability_id'],
  severity: ['severity', 'threat_level', 'risk', 'criticality', 'cvss_score', 'score'],
  verdict: ['verdict', 'classification', 'status', 'malicious', 'threat_type'],
  source: ['source', 'provider', 'feed', 'reporter'],
  time: ['time', 'timestamp', 'created_at', 'first_seen', 'last_seen', 'date', 'reported_at'],
  country: ['country', 'country_code', 'countryCode', 'geo', 'location'],
  isp: ['isp', 'org', 'organization', 'asn', 'as_name'],
  tag: ['tag', 'tags', 'label', 'labels', 'category', 'type'],
  description: ['description', 'desc', 'detail', 'details', 'summary', 'comment'],
}

/** Well-known security API base URLs */
export const PROVIDER_DOMAINS: Record<string, string> = {
  'abuse.ch': 'abuse.ch',
  abuseipdb: 'api.abuseipdb.com',
  virustotal: 'www.virustotal.com',
  greynoise: 'api.greynoise.io',
  shodan: 'api.shodan.io',
  ipinfo: 'ipinfo.io',
  nvd: 'services.nvd.nist.gov',
  crtsh: 'crt.sh',
  urlscan: 'urlscan.io',
  censys: 'search.censys.io',
}

/** Exit codes following CLI specification */
export const EXIT_CODES = {
  SUCCESS: 0,
  RUNTIME_ERROR: 1,
  BAD_ARGUMENT: 2,
  AUTH_FAILED: 3,
  PERMISSION_DENIED: 4,
  NOT_FOUND: 5,
  SECURITY_ISSUE_FOUND: 10,
  USER_INTERRUPT: 130,
} as const
