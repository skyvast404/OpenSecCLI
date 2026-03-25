---
name: ctf-toolkit
description: >
  Trigger when user mentions "CTF", "capture the flag", "find the flag",
  "decode this", "what type of hash", "analyze this binary", "steganography",
  "forensics challenge", "crypto challenge", "reverse engineering". Use for
  CTF competition challenges across crypto, forensics, and binary exploitation
  categories.
---

# CTF Toolkit Skill

Assist with Capture The Flag competition challenges by classifying the problem
type, running appropriate OpenSecCLI tools, and guiding the user through a
structured solution path.

## 1. Required Input

At least one of the following:

- **Challenge file** (`$FILE`): Path to a file (binary, PCAP, image, etc.)
- **Hash string** (`$HASH`): A hash or encoded string to identify/crack
- **URL or IP** (`$TARGET`): A target for web or OSINT challenges
- **Challenge description**: Free-text description of the challenge

If the user provides insufficient context, ask clarifying questions before
proceeding.

## 2. Challenge Classification

Classify the challenge into one or more categories:

| Indicator | Category |
|-----------|----------|
| Hex string, encoded text, cipher reference | **Crypto** |
| File to analyze, disk image, memory dump, PCAP | **Forensics** |
| Binary/ELF, buffer overflow, ROP, shellcode | **Binary/Pwn** |
| Hidden data in images, audio files | **Steganography** |
| Domain, IP, username, social media | **OSINT** |
| Web URL, SQL injection, XSS, cookies | **Web** |
| Misc puzzles, encoding chains | **Misc** |

If classification is ambiguous, run initial analysis to determine the type.

## 3. Crypto Challenges

### Step 1 — Hash/Encoding Identification

```bash
opensec crypto hash-id --hash "$HASH" --format json
```

This identifies the hash type (MD5, SHA1, SHA256, bcrypt, etc.) or encoding
scheme (Base64, Base32, hex, ROT13, etc.).

### Step 2 — Cracking Guidance

Based on the identified type, suggest appropriate commands:

| Hash Type | Suggested Approach |
|-----------|--------------------|
| MD5/SHA1 | `hashcat -m 0/100 hash.txt wordlist.txt` or online rainbow tables |
| SHA256 | `hashcat -m 1400 hash.txt rockyou.txt` |
| bcrypt | `hashcat -m 3200 hash.txt wordlist.txt` (slow, use small wordlist) |
| Base64 | `echo "$ENCODED" \| base64 -d` |
| Hex | `echo "$HEX" \| xxd -r -p` |
| ROT13 | `echo "$TEXT" \| tr 'A-Za-z' 'N-ZA-Mn-za-m'` |

### Step 3 — Advanced Crypto Attacks

Guide through common patterns:
- **XOR cipher**: Try single-byte XOR brute force, look for known plaintext
- **RSA**: Check for small e, common n factorization, Wiener's attack
- **Vigenere**: Frequency analysis, Kasiski examination
- **AES-ECB**: Look for repeating blocks (ECB penguin pattern)

## 4. Forensics Challenges

### Step 1 — File Analysis

```bash
opensec forensics file-analyze --file $FILE --format json
```

Runs `file`, `strings`, `exiftool`, and `binwalk` to identify file type,
embedded data, metadata, and hidden archives.

### Step 2 — Format-Specific Analysis

**If PCAP/PCAPNG:**

```bash
opensec forensics pcap-summary --file $FILE --format json
```

Extracts protocol statistics, HTTP objects, DNS queries, TCP streams,
and potential credentials. Look for:
- HTTP file downloads (exported objects)
- DNS exfiltration (long subdomain labels)
- Cleartext credentials in FTP/HTTP/SMTP

**If binary/ELF:**

```bash
opensec forensics binary-check --file $FILE --format json
```

Checks binary protections and extracts metadata. See Binary/Pwn section.

**If disk image or memory dump:**
- Guide through `volatility` for memory forensics
- Suggest `autopsy` or `sleuthkit` for disk images
- Look for deleted files, browser history, registry hives

### Step 3 — Data Recovery Techniques

- **Binwalk extraction**: `binwalk -e $FILE` for embedded files
- **Foremost/scalpel**: Carve files from raw data
- **Strings with context**: `strings -n 8 $FILE | grep -i flag`

## 5. Steganography Challenges

### Detection Workflow

1. Check file metadata: `exiftool $FILE`
2. Check for appended data: `binwalk $FILE`
3. LSB analysis for images: suggest `zsteg` (PNG/BMP) or `stegsolve`
4. For JPEG: suggest `steghide extract -sf $FILE`
5. For audio: suggest spectogram analysis with `sox` or Audacity
6. Check for null bytes or whitespace encoding in text files

Common flag hiding locations:
- EXIF comments or GPS coordinates
- LSB of RGB channels
- Appended after EOF marker
- Alpha channel of PNG images
- Trailing whitespace (whitespace steganography)

## 6. Binary/Pwn Challenges

### Step 1 — Binary Protections Check

```bash
opensec forensics binary-check --file $FILE --format json
```

### Step 2 — Exploitation Guidance by Protection

| Protection | Status | Approach |
|------------|--------|----------|
| NX | Disabled | Shellcode on stack, ret2shellcode |
| NX | Enabled | ROP chains, ret2libc, ret2plt |
| PIE | Disabled | Hardcoded addresses available |
| PIE | Enabled | Need info leak first, partial overwrites |
| Canary | Disabled | Direct buffer overflow |
| Canary | Enabled | Canary leak via format string, brute force (fork) |
| RELRO | Partial | GOT overwrite viable |
| RELRO | Full | Target `__malloc_hook`, `__free_hook`, or stack |

### Step 3 — Pwntools Skeleton

Suggest starter script based on protections:

```python
from pwn import *

elf = ELF('./$BINARY')
# p = process('./$BINARY')  # local
p = remote('$HOST', $PORT)  # remote

# Overflow offset (find with cyclic pattern)
offset = cyclic_find(0x61616161)  # adjust after crash analysis

payload = b'A' * offset
# Add exploit-specific payload here

p.sendline(payload)
p.interactive()
```

## 7. OSINT Challenges

Run relevant recon commands based on the target type:

**Domain target:**

```bash
opensec recon subdomain-enum --domain $DOMAIN --format json
```

```bash
opensec recon tech-fingerprint --target $URL --format json
```

**IP target:**

```bash
opensec shodan host-lookup --ip $IP --format json
```

Guide through:
- WHOIS history and registration details
- Wayback Machine for historical snapshots
- Google dorking for indexed sensitive files
- Social media OSINT for username pivoting
- Certificate transparency logs for related domains

## 8. Error Handling

- If a command fails, note it and try alternative approaches. CTF tools often
  need creative fallbacks.
- If a file path is invalid, ask the user to verify the path.
- If the challenge type is unclear after initial analysis, present the raw
  tool output and ask the user for more context.

## 9. Output Report Format

Present findings as a structured walkthrough:

```markdown
# CTF Solution Walkthrough

**Challenge:** <name if provided>
**Category:** Crypto | Forensics | Binary/Pwn | Stego | OSINT | Web | Misc
**Difficulty:** Easy | Medium | Hard (estimated)
**Analyzed:** <current date/time>

---

## Challenge Analysis

<1-2 sentence summary of what the challenge presents.>

## Tool Output Summary

### <Tool/Command>
- **Key findings:** <relevant details from each tool run>

---

## Solution Path

### Step 1: <First action>
<Explanation of what to do and why.>

### Step 2: <Next action>
<Explanation.>

### Step N: <Flag extraction>
<How to get the flag.>

---

## Flag Format Hints

- Common formats: `flag{...}`, `CTF{...}`, `FLAG{...}`, `picoCTF{...}`
- Check for: hex-encoded flags, base64-wrapped flags, flags split across
  multiple locations
- If no flag found: re-examine with different tools, check for multi-stage
  challenges

---

## Alternative Approaches

- <Other methods that could work>
- <Tools or techniques to try if primary path fails>
```

## 10. Follow-up Suggestions

After presenting the walkthrough, offer next steps:

- "Want me to try a different analysis tool on the file?"
- "Should I decode the output using a different encoding scheme?"
- "I can check the binary for more exploitation vectors if needed."
- "Want me to run deeper OSINT on any domains or IPs we found?"

Offer these based on the specific challenge context.
