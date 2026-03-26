/**
 * Security domain taxonomy for adapter classification.
 * Used for `opensec list --domain <domain>` filtering and plugin categorization.
 */
export const SECURITY_DOMAINS = {
  'threat-intel': 'Threat intelligence feeds and reputation lookups',
  'code-security': 'Static analysis, SAST, code review',
  'recon': 'Reconnaissance, asset discovery, OSINT',
  'vuln-scan': 'Vulnerability scanning, misconfig detection',
  'secrets': 'Secret and credential detection',
  'supply-chain': 'Dependency audit, CI/CD security, SBOM',
  'cloud-security': 'Cloud posture, IaC, containers, Kubernetes',
  'forensics': 'File analysis, binary reverse engineering, PCAP, mobile',
  'pentest': 'Active testing utilities (HTTP, race conditions)',
  'agent-security': 'Agent security assessment (attack patterns, detection, defense)',
  'dast': 'Dynamic application security testing',
} as const

export type SecurityDomain = keyof typeof SECURITY_DOMAINS

/**
 * Maps provider names to their default domain.
 * Used when a YAML adapter doesn't explicitly set domain.
 */
export const PROVIDER_DOMAIN_MAP: Record<string, SecurityDomain> = {
  // Threat intelligence
  'abuse.ch': 'threat-intel',
  'abuseipdb': 'threat-intel',
  'virustotal': 'threat-intel',
  'greynoise': 'threat-intel',
  'ipinfo': 'threat-intel',
  'shodan': 'threat-intel',
  'crtsh': 'threat-intel',
  'nvd': 'threat-intel',
  'enrichment': 'threat-intel',
  // Code security
  'scan': 'code-security',
  // Recon
  'recon': 'recon',
  // Vuln scanning
  'vuln': 'vuln-scan',
  // Secrets
  'secrets': 'secrets',
  // Supply chain
  'supply-chain': 'supply-chain',
  // Cloud
  'cloud': 'cloud-security',
  // Forensics
  'forensics': 'forensics',
  'crypto': 'forensics',
  // Pentest
  'pentest': 'pentest',
  // Agent security
  'agent-security': 'agent-security',
  // DAST
  'dast': 'dast',
}
