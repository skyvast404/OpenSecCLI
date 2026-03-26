---
name: threat-hunting
description: >
  Trigger when user asks to "hunt for threats", "investigate suspicious
  activity", "proactive threat detection", "check these IOCs", "threat
  intelligence analysis", "are we compromised", "analyze these indicators",
  "correlate threat data", "MITRE ATT&CK mapping", "threat hunt across
  indicators". Use for proactive threat hunting using multi-source enrichment
  and cross-IOC correlation.
---

# Proactive Threat Hunting

Orchestrate a multi-source threat hunting operation using OpenSecCLI adapters.
Extracts indicators of compromise (IOCs) from user input, enriches each through
parallel intelligence queries, cross-correlates findings, maps to MITRE ATT&CK,
and produces an actionable threat hunting report.

## 1. IOC Extraction

Parse the user's input to extract all indicators. Classify each using:

| Pattern | Type | Examples |
|---------|------|---------|
| IPv4 `\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}` | `ip` | `8.8.8.8` |
| IPv6 (contains `::` or 4+ colon-separated hex groups) | `ip` | `2001:db8::1` |
| 32 hex chars | `hash` (MD5) | `d41d8cd98f00b204...` |
| 40 hex chars | `hash` (SHA1) | `da39a3ee5e6b4b0d...` |
| 64 hex chars | `hash` (SHA256) | `e3b0c44298fc1c14...` |
| Starts with `http://` or `https://` | `url` | `https://evil.com/payload` |
| Valid hostname with TLD, no scheme | `domain` | `evil.example.com` |

If the user provides free-form text (log entries, alert descriptions, email
headers), scan for embedded IOCs. List all extracted IOCs for user confirmation
before proceeding with enrichment.

---

## 2. Enrichment Queries

Run ALL relevant queries for each IOC type. Append `--format json` to all
commands. Launch all queries across all IOCs in parallel.

### IP Addresses

```bash
opensec enrichment ip-enrich --ip $IP --format json
```

`ip-enrich` fans out to AbuseIPDB, VirusTotal, GreyNoise, ipinfo, and
ThreatFox. Captures: abuse confidence, detection ratio, noise classification,
geolocation, ASN, associated malware families.

### Domains

```bash
opensec enrichment domain-enrich --domain $DOMAIN --format json
```

Captures: WHOIS data, reputation scores, threat feed matches, registrar,
creation date, SSL certificate details, passive DNS records.

### File Hashes (MD5 / SHA1 / SHA256)

```bash
opensec enrichment hash-enrich --hash $HASH --format json
```

Captures: VirusTotal detection ratio, malware family, file type, first/last
seen, sandbox verdicts, MalwareBazaar tags.

### URLs

```bash
opensec enrichment url-enrich --url $URL --format json
```

Captures: URLhaus status, payload info, VirusTotal scan results, ThreatFox
IOC matches, associated malware families.

---

## 3. CVE Correlation

After enrichment, if any IOC is associated with a known vulnerability or
software version, query for related CVEs:

```bash
opensec nvd cve-search --keyword $KEYWORD --format json
```

Use keywords derived from:
- Malware family names found in enrichment results
- Software/service versions from Shodan or enrichment data
- Vulnerability references in threat feed matches

---

## 4. Cross-IOC Correlation

After all enrichment data is collected, perform correlation analysis:

1. **Infrastructure overlap**: Do multiple IOCs resolve to or reference the
   same IP address, ASN, or hosting provider?
2. **Campaign linkage**: Are IOCs linked through the same malware family,
   threat actor, or ThreatFox campaign tag?
3. **Temporal proximity**: Do first-seen / last-seen dates cluster together,
   suggesting a coordinated operation?
4. **Kill chain mapping**: Do the IOCs represent different stages of an
   attack (e.g., phishing domain --> C2 IP --> payload hash)?
5. **Common registrar/infrastructure**: Domains sharing registrar, name
   servers, or IP ranges may indicate actor infrastructure.

---

## 5. Verdict Logic

Assign a verdict to each IOC individually:

| Condition | Verdict |
|-----------|---------|
| ANY source flags as malicious (VT detections >= 5, AbuseIPDB confidence >= 75, GreyNoise = "malicious", ThreatFox/MalwareBazaar match, URLhaus = "malware_download") | **Malicious** |
| Mixed signals: some flags but below thresholds (VT 1-4, AbuseIPDB 25-74, suspicious but not confirmed) | **Suspicious** |
| All sources return clean with no detections | **Clean** |
| Insufficient data from most sources | **Unknown** |

Then assign an overall hunt verdict:
- **Active Threat**: Multiple malicious IOCs with confirmed correlation
- **Probable Threat**: Mix of malicious/suspicious with some correlation
- **Inconclusive**: Mixed results, no strong correlation
- **No Threat Detected**: All IOCs clean, no concerning patterns

---

## 6. MITRE ATT&CK Mapping

Map findings to MITRE ATT&CK techniques where identifiable:

| IOC Evidence | Technique | Tactic |
|-------------|-----------|--------|
| Phishing domain | T1566 Phishing | Initial Access |
| C2 IP with beaconing pattern | T1071 Application Layer Protocol | Command & Control |
| Malware hash (trojan) | T1204 User Execution | Execution |
| DNS tunneling indicators | T1572 Protocol Tunneling | Command & Control |
| Credential harvesting URL | T1056 Input Capture | Collection |

Include technique IDs, names, tactics, and a brief rationale for the mapping.

---

## Error Handling

- If an enrichment command fails (non-zero exit, timeout, missing API key),
  mark that source as `Unavailable` and continue with remaining sources.
- If ALL commands fail for a given IOC, mark as `Unknown` and suggest the
  user check API configuration with `opensec config show`.
- Never let a single failed query abort the entire hunt.
- Parse JSON safely. Non-JSON output is treated as errored.

---

## Output --- Threat Hunting Report

### 1. Hunt Summary

```
Hunt Date:          <current date>
IOCs Analyzed:      <N>
  IPs: <n>   Domains: <n>   Hashes: <n>   URLs: <n>
Sources Queried:    <list>
Sources Unavailable: <list or "None">

Overall Verdict:    Active Threat / Probable Threat / Inconclusive / No Threat
```

One-paragraph threat narrative: what was found, confidence level, and
recommended urgency.

### 2. IOC Verdicts

Table with columns: #, IOC, Type, Verdict, Key Evidence, Sources Queried.

### 3. Detailed Enrichment Results

For each IOC, a per-source table: Source, Status, Key Findings.
Include all queried sources with their detection details.

### 4. Cross-IOC Correlation Map

ASCII graph showing relationships between IOCs (resolves-to, hosts,
downloaded-from, same-campaign). Explain each link's significance.

### 5. MITRE ATT&CK Coverage

Table with columns: Tactic, Technique (ID + name), IOC Evidence, Confidence.

### 6. Related CVEs

Table with columns: CVE, CVSS, Description, Relevance to hunt.

### 7. Recommended Actions

**If Active Threat**: Block IOCs at perimeter, search SIEM/EDR for historical
connections, isolate affected endpoints, preserve forensic evidence, escalate.

**If Probable/Inconclusive**: Add to monitoring watchlist, search 30-90 day
logs, correlate with internal alerts, re-evaluate in 24-48 hours.

**Documentation**: Record IOCs in TIP, update detection rules from ATT&CK
mappings, share with ISACs.

---

## Follow-up Suggestions

After presenting the report, offer relevant next steps:

- "Want me to investigate related IPs/domains found in the enrichment?"
- "I can search for additional IOCs associated with the same campaign."
- "Should I check if any of the related CVEs affect your infrastructure?"
- "I can create detection rules based on the MITRE ATT&CK mappings."
- "Want me to run a deeper OSINT dive on any of the malicious domains?"
