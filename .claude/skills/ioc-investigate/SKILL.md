---
name: ioc-investigate
description: >
  Trigger when user mentions IP addresses, domains, file hashes, URLs in a
  security context, or asks to "investigate", "check", "lookup", "analyze" an
  indicator. Also trigger for phrases like "is this IP malicious", "check this
  hash", "what do we know about this domain". Use this skill proactively
  whenever security indicators appear in conversation.
---

# IOC Investigation Skill

Orchestrate multi-source threat intelligence lookups for Indicators of Compromise
using OpenSecCLI, then correlate results into a structured threat assessment.

## 1. IOC Type Detection

Classify the indicator before querying. Use these rules:

| Pattern | Type | Examples |
|---------|------|---------|
| IPv4 `\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}` | `ip` | `8.8.8.8`, `192.168.1.1` |
| IPv6 (contains `::` or 4+ colon-separated hex groups) | `ip` | `2001:db8::1` |
| 32 hex chars | `hash` (MD5) | `d41d8cd98f00b204e9800998ecf8427e` |
| 40 hex chars | `hash` (SHA1) | `da39a3ee5e6b4b0d3255bfef95601890afd80709` |
| 64 hex chars | `hash` (SHA256) | `e3b0c44298fc1c149afbf4c8996fb924...` |
| Starts with `http://` or `https://` | `url` | `https://evil.example.com/payload` |
| Valid hostname with TLD, no scheme | `domain` | `evil.example.com` |

If multiple IOCs are provided, investigate each one. Group results per IOC.

## 2. Query Matrix

Run ALL relevant commands for each IOC type. Always append `--format json` for
machine-parseable output.

### IP Address

Run these in parallel via separate Bash tool calls:

```bash
opensec enrichment ip-enrich --ip <ip> --format json
```

```bash
opensec shodan host-lookup --ip <ip> --format json
```

`ip-enrich` already fans out to AbuseIPDB, VirusTotal, GreyNoise, ipinfo, and
ThreatFox. Shodan adds open-port and service-banner context.

### File Hash (MD5 / SHA1 / SHA256)

Run these in parallel:

```bash
opensec virustotal hash-lookup --hash <hash> --format json
```

```bash
opensec abuse.ch malwarebazaar-query --hash <hash> --format json
```

### Domain

Run these in parallel:

```bash
opensec virustotal domain-lookup --domain <domain> --format json
```

```bash
opensec abuse.ch threatfox-search --query <domain> --format json
```

### URL

Extract the domain from the URL, then run in parallel:

```bash
opensec abuse.ch urlhaus-query --url <url> --format json
```

```bash
opensec virustotal domain-lookup --domain <extracted-domain> --format json
```

```bash
opensec abuse.ch threatfox-search --query <url> --format json
```

## 3. Error Handling

- If a command fails (non-zero exit, timeout, API key missing), note the source
  as `unavailable` in the report. Do NOT stop the investigation.
- If ALL commands fail, report that no sources could be reached and suggest the
  user check API key configuration with `opensec config show`.
- Parse JSON output with `JSON.parse`-safe handling. If output is not valid JSON,
  treat that source as errored and include the raw stderr in the report.

## 4. Verdict Logic

After collecting all results, determine a verdict:

| Condition | Verdict |
|-----------|---------|
| ANY source flags the IOC as **malicious** (e.g., VT detections >= 5, AbuseIPDB confidence >= 75, GreyNoise classification = "malicious", ThreatFox/MalwareBazaar match found, URLhaus threat = "malware_download") | **Malicious** |
| Mixed signals: some sources flag suspicious activity but below malicious thresholds (e.g., VT detections 1-4, AbuseIPDB confidence 25-74, GreyNoise = "benign" but with scan activity) | **Suspicious** |
| All sources return clean results with no detections | **Clean** |
| Insufficient data (most sources returned no results or errored) | **Unknown** |

Use judgment when thresholds overlap. Err on the side of caution -- if in doubt
between Clean and Suspicious, choose Suspicious.

## 5. Output Report Format

Present the final report in this exact markdown structure:

```markdown
# IOC Investigation Report

**Indicator:** `<the IOC value>`
**Type:** IP Address | Domain | File Hash (SHA256) | URL
**Investigated:** <current date/time>

---

## Verdict: <Malicious | Suspicious | Clean | Unknown>

<1-2 sentence summary explaining the verdict rationale.>

---

## Source Results

### <Source Name 1> (e.g., VirusTotal)
- **Status:** Queried successfully | Unavailable | Error
- **Key findings:**
  - Detection ratio: 12/70
  - Tags: trojan, banker
  - First seen: 2025-01-15
  - ...relevant fields

### <Source Name 2> (e.g., AbuseIPDB)
- **Status:** Queried successfully
- **Key findings:**
  - Abuse confidence: 87%
  - Total reports: 342
  - ISP: Example Hosting
  - Country: RU
  - ...relevant fields

### <Source Name N>
...

---

## Threat Context

- **MITRE ATT&CK:** <relevant technique IDs if identifiable, e.g., T1071 Application Layer Protocol>
- **Associated malware families:** <if reported by any source>
- **Related infrastructure:** <other IPs, domains, hashes mentioned in results>
- **First seen / Last seen:** <earliest and latest dates across sources>

---

## Recommended Actions

1. <Specific action based on verdict and IOC type>
2. <e.g., "Block IP at perimeter firewall and add to SIEM watchlist">
3. <e.g., "Quarantine any hosts that communicated with this indicator">
4. <e.g., "Search proxy logs for connections to this domain in the last 30 days">
5. <e.g., "Submit hash to sandbox for dynamic analysis">
```

## 6. Recommended Actions by Verdict

Tailor the recommended actions to the verdict:

### Malicious
- Block the indicator at perimeter (firewall, proxy, DNS sinkhole)
- Add to SIEM/SOAR watchlist for retroactive and future detection
- Search historical logs for any prior communication with this indicator
- Quarantine/isolate affected endpoints if connections found
- Escalate to incident response if active compromise is indicated
- Preserve forensic evidence (memory dumps, disk images)

### Suspicious
- Add to monitoring watchlist (do NOT block yet without confirmation)
- Investigate historical connections in proxy/DNS/firewall logs
- Correlate with other IOCs from the same investigation
- Request additional context from threat intel team
- Re-evaluate in 24-48 hours with updated threat data

### Clean
- No immediate action required
- Consider adding to baseline allowlist if this is expected traffic
- Document the investigation for audit trail

### Unknown
- Retry investigation after verifying API key configuration
- Submit to additional sources manually (e.g., sandbox, manual OSINT)
- Flag for analyst review -- do not auto-close

## 7. Multi-IOC Investigations

When the user provides multiple IOCs:

1. Investigate each IOC individually using the query matrix above
2. Run ALL queries for ALL IOCs in parallel (maximize parallel Bash calls)
3. After all results are collected, add a **Correlation** section at the end:

```markdown
## Cross-IOC Correlation

- IOCs `<A>` and `<B>` are linked: both appear in ThreatFox under campaign X
- Domain `<C>` resolves to IP `<A>` per VirusTotal passive DNS
- Hash `<D>` was downloaded from URL `<E>` per MalwareBazaar
```

4. If correlations are found, upgrade the overall assessment accordingly

## 8. Follow-up Suggestions

After presenting the report, proactively suggest next steps:

- "Want me to check any related IPs/domains found in the results?"
- "Should I search for this hash in URLhaus to check distribution URLs?"
- "I can run a deeper Shodan search on the open ports if needed."

Offer these only when the results contain leads worth pursuing.
