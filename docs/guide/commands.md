# Commands

84 commands across 11 security domains. Commands marked **pure TS** require zero external dependencies.

## Threat Intelligence (no API key)

| Command | Description |
|---------|-------------|
| `opensec abuse.ch urlhaus-query --url <url>` | URLhaus malicious URL check |
| `opensec abuse.ch malwarebazaar-query --hash <hash>` | MalwareBazaar malware sample lookup |
| `opensec abuse.ch threatfox-search --ioc <ioc>` | ThreatFox IOC search |
| `opensec abuse.ch feodo-list` | Feodo Tracker botnet C&C list |
| `opensec abuse.ch sslbl-search --hash <sha1>` | SSLBL malicious SSL cert search |
| `opensec nvd cve-get <cve-id>` | CVE details |
| `opensec nvd cve-search --keyword <term>` | CVE keyword search |
| `opensec crtsh cert-search --domain <domain>` | Certificate transparency search |

## Threat Intelligence (free-tier API key)

| Command | Free Tier |
|---------|-----------|
| `opensec abuseipdb ip-check <ip>` | 1,000/day |
| `opensec virustotal hash-lookup <hash>` | 500/day |
| `opensec virustotal ip-lookup <ip>` | 500/day |
| `opensec virustotal domain-lookup <domain>` | 500/day |
| `opensec greynoise ip-check <ip>` | 50/day |
| `opensec ipinfo ip-lookup <ip>` | 50K/month |
| `opensec shodan host-lookup <ip>` | Limited |

## Multi-Source Enrichment

| Command | Sources |
|---------|---------|
| `opensec enrichment ip-enrich <ip>` | AbuseIPDB + VirusTotal + GreyNoise + ipinfo + ThreatFox |
| `opensec enrichment domain-enrich <domain>` | Multi-source domain intelligence |
| `opensec enrichment hash-enrich <hash>` | Multi-source hash reputation |
| `opensec enrichment url-enrich <url>` | Multi-source URL analysis |

## Recon

| Command | Backend |
|---------|---------|
| `opensec recon subdomain-enum <domain>` | subfinder / amass |
| `opensec recon tech-fingerprint <target>` | httpx / whatweb |
| `opensec recon port-scan <target>` | nmap / masscan |
| `opensec recon fast-scan <target>` | masscan |
| `opensec recon content-discover <url>` | ffuf / dirsearch |
| `opensec recon dns-resolve <domain>` | dnsx |
| `opensec recon url-crawl <url>` | katana |
| `opensec recon url-archive <domain>` | gau |
| `opensec recon wayback-urls <domain>` | waybackurls |
| `opensec recon web-spider <url>` | gospider |
| `opensec recon param-discover <url>` | paramspider |
| `opensec recon osint-harvest <domain>` | theHarvester |

## Vulnerability Scanning

| Command | Backend |
|---------|---------|
| `opensec vuln nuclei-scan <target>` | nuclei |
| `opensec vuln nikto-scan <target>` | nikto |
| `opensec vuln header-audit <url>` | **pure TS** — CSP parsing, cookie analysis, A-F grading |
| `opensec vuln tls-check <host>` | testssl.sh |
| `opensec vuln cors-check <url>` | **pure TS** — CORS misconfiguration detection |
| `opensec vuln api-discover <url>` | kiterunner / ffuf |
| `opensec vuln xss-scan <url>` | dalfox |
| `opensec vuln crlf-scan <url>` | crlfuzz |
| `opensec vuln graphql-audit <url>` | graphql introspection |

## Pentest Utilities

| Command | Backend |
|---------|---------|
| `opensec pentest http-request <url>` | **pure TS** — crafted HTTP requests |
| `opensec pentest race-test <url>` | **pure TS** — concurrent race condition tester |
| `opensec pentest fuzz <url>` | **pure TS** — parameter fuzzing with XSS/SQLi/traversal payloads |
| `opensec pentest jwt-test <token>` | **pure TS** — JWT vulnerability testing |
| `opensec pentest sqli-scan <url>` | sqlmap |
| `opensec pentest cmdi-scan <url>` | commix |

## SAST & Scan Pipeline

| Command | Description |
|---------|-------------|
| `opensec scan full <path>` | Full pipeline: discover, analyze, report |
| `opensec scan discover <path>` | Build security-focused project map |
| `opensec scan analyze <path>` | Static analysis (semgrep, gitleaks) + custom rules |
| `opensec scan report <path>` | Generate reports (JSON, SARIF, Markdown) |
| `opensec scan entrypoints <path>` | Find HTTP routes, RPC handlers, entry points |
| `opensec scan git-signals <path>` | Extract security-relevant commits |
| `opensec scan context-builder <path>` | Build code context bundles for LLM analysis |
| `opensec scan triage-memory` | False-positive tracking and skip logic |
| `opensec scan benchmark <path>` | Scanner benchmarks (precision/recall/F1) |
| `opensec scan gosec-scan <path>` | Go security scanner |
| `opensec scan bandit-scan <path>` | Python security linter |

## Agent Security

| Command | Description |
|---------|-------------|
| `opensec agent-security scan-skill <path>` | Scan Claude Code skills for prompt injection & data exfil |
| `opensec agent-security mcp-audit <path>` | Audit MCP server tools for poisoning & rug-pull risks |
| `opensec agent-security grade-results <file>` | Grade results: SAFE / UNSAFE / BLOCKED / INCONCLUSIVE |
| `opensec agent-security analyze-coverage <file>` | Coverage vs OWASP ASI Top 10 & MITRE ATLAS |
| `opensec agent-security defense-validation <file>` | Precision / recall / F1 scoring |
| `opensec agent-security manage-kb` | Manage attack pattern & detection rule knowledge base |
| `opensec agent-security normalize-cases <file>` | Normalize raw test sources into canonical format |
| `opensec agent-security generate-variants <file>` | Expand suite manifests into mutated test cases |
| `opensec agent-security write-report <file>` | Generate assessment report from grading results |

## Supply Chain

| Command | Backend |
|---------|---------|
| `opensec supply-chain dep-audit [path]` | npm-audit + pip-audit + trivy |
| `opensec supply-chain ci-audit [path]` | **pure TS** — CI config security check |
| `opensec supply-chain sbom [path]` | syft |
| `opensec supply-chain snyk-scan [path]` | snyk |

## Cloud Security

| Command | Backend |
|---------|---------|
| `opensec cloud iac-scan [path]` | checkov / terrascan |
| `opensec cloud container-scan <image>` | trivy / grype |
| `opensec cloud kube-audit` | kube-bench |
| `opensec cloud dockerfile-lint <path>` | hadolint |
| `opensec cloud kube-security` | kubesec |
| `opensec cloud container-lint <image>` | dockle |
| `opensec cloud cloud-posture` | prowler / scout suite |

## Secrets

| Command | Backend |
|---------|---------|
| `opensec secrets trufflehog-scan <target>` | trufflehog |

## Forensics

| Command | Backend |
|---------|---------|
| `opensec forensics file-analyze <file>` | file + exiftool + strings + binwalk |
| `opensec forensics binary-check <binary>` | checksec |
| `opensec forensics pcap-summary <pcap>` | tshark |
| `opensec forensics apk-analyze <apk>` | aapt + strings |

## Crypto

| Command | Backend |
|---------|---------|
| `opensec crypto hash-id <hash>` | **pure TS** — identify hash type + hashcat/john format |

## DAST

| Command | Backend |
|---------|---------|
| `opensec dast zap-scan <target>` | OWASP ZAP |

See [CLI Reference](/api/cli-reference) for detailed argument descriptions.
