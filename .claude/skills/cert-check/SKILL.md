---
name: cert-check
description: >
  Trigger when user asks to "check certificates for", "find subdomains via certs",
  "certificate transparency lookup", "SSL cert status". Certificate transparency intelligence.
---

# Cert Check

Query certificate transparency logs for a domain using the free crt.sh API (no key needed).

## Workflow

### Step 1: Certificate Search

```bash
opensec crtsh cert-search --domain $DOMAIN --format json
```

Parse JSON output. Extract:
- All discovered subdomains (from common_name and name_value fields)
- Certificate issuers (issuer_name / issuer_ca_id)
- Not-before and not-after dates
- Wildcard certificates (entries containing `*`)
- Total certificate count

### Step 2: Analyze Results

Flag the following:
- **Expired certificates:** not_after date is in the past
- **Expiring soon:** not_after within 30 days
- **Wildcard certs:** any common_name starting with `*.`
- **Large attack surface:** more than 20 unique subdomains
- **Unusual issuers:** any non-standard or self-signed CAs

### Step 3: Present Report

```markdown
# Certificate Transparency Report

**Domain:** <domain>
**Certificates Found:** <count>
**Unique Subdomains:** <count>
**Checked:** <current date/time>

## Subdomains Discovered
| Subdomain | Issuer | Valid Until | Status |
|-----------|--------|-------------|--------|
| www.example.com | Let's Encrypt | 2025-06-01 | Valid |
| *.example.com | DigiCert | 2024-12-01 | Expired |
| ... | ... | ... | ... |

## Alerts
- <Expired cert for subdomain X>
- <Wildcard cert detected: *.example.com>
- <Large attack surface: N subdomains found>

## Summary
<2-3 sentences: overall cert health, key risks, subdomain count context>
```

## Error Handling

- If cert-search fails or times out (crt.sh can be slow), retry once with `--timeout 30`.
- If still failing, report "crt.sh unavailable" and suggest trying later.
