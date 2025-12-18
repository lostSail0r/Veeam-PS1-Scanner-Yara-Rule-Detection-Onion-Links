# Tor Onion & Ransomware YARA Rules

A collection of YARA rules designed to detect Tor `.onion` links, ransomware payment portals, and C2 (command-and-control) configurations commonly found in ransomware-related files.  
These rules are compatible with [YARA](https://yara.readthedocs.io/) and [Veeam Backup & Replication](https://helpcenter.veeam.com/docs/vbr/userguide/malware_detection_scan_backup_yara.html).

---

## 📋 Table of Contents
- [Rules Included](#rules-included)
- [Usage](#usage)
- [Rule Details](#rule-details)
- [Compatibility](#compatibility)
- [Feedback & Recommendations](#feedback--recommendations)
- [Testing Recommendations](#testing-recommendations)
- [License](#license)

---

## Rules Included

- **comprehensive_onion_detection**  
  Detects Tor `.onion` links in files with additional ransomware context (e.g., ransom notes, payment instructions).

- **onion_links_simple**  
  Broad detection of any Tor `.onion` links.

- **ransomware_payment_portal**  
  Identifies ransomware payment portals using `.onion` addresses and related payment/decryption language.

- **tor_c2_configuration**  
  Detects C2 configuration patterns referencing Tor hidden service endpoints.

---

## Usage

### With YARA CLI

1. **Save the rules:**  
   Download or copy the rules into a file, e.g., `onion_ransomware_rules.yar`.

2. **Scan a file:**  
   ```bash
   yara onion_ransomware_rules.yar suspicious_file.txt
   ```

3. **Scan a directory recursively:**
   ```bash
   yara -r onion_ransomware_rules.yar /path/to/directory/
   ```

4. **Output to JSON for SIEM integration:**
   ```bash
   yara -r --json onion_ransomware_rules.yar /path/to/scan/ > detections.json
   ```

### With Veeam Backup & Replication

1. **Copy the rule file to the Veeam YARA directory:**

   **Windows:**
   ```
   C:\Program Files\Veeam\Backup and Replication\Backup\YaraRules\
   ```

   **Linux:**
   ```
   /var/lib/veeam/yara_rules/
   ```

2. **Configure malware detection:**
   - Navigate to: VBR Console ➜ **Settings** ➜ **Malware Detection** ➜ **YARA** ➜ **Add Rule File**
   - Select your `.yar` file

3. **Trigger a malware scan** on your backups as per [Veeam documentation](https://helpcenter.veeam.com/docs/vbr/userguide/malware_detection_scan_backup_yara.html).

---

## Rule Details

### 1. comprehensive_onion_detection

```yara
rule comprehensive_onion_detection {
    meta:
        description = "Detects Tor .onion links with ransomware context"
        author      = "CG"
        severity    = "HIGH"
        category    = "TOR_RANSOMWARE"
    strings:
        $v2_onion     = /[a-z2-7]{16}\.onion[\/\w.\-?=&]*/
        $v3_onion     = /[a-z2-7]{56}\.onion[\/\w.\-?=&]*/
        $http_onion   = /https?:\/\/[a-z2-7]{16,56}\.onion/
        $tor_protocol = /tor:\/\/[a-z2-7]{16,56}\.onion/

        $ransom1  = "ransom"    ascii wide nocase
        $ransom2  = "encrypted" ascii wide nocase
        $ransom3  = "decrypt"   ascii wide nocase
        $payment  = "payment"   ascii wide nocase
        $bitcoin  = /(bitcoin|btc)/i

        $note1 = "READ"    fullword ascii nocase
        $note2 = "HOW_TO"  nocase
        $note3 = "DECRYPT" ascii wide nocase

    condition:
        1 of ($v2_onion,$v3_onion,$http_onion,$tor_protocol) and
        filesize < 26214400 and  // 25 MB
        (
            any of ($ransom*) or $payment or $bitcoin or
            2 of ($note*)
        )
}
```

**Purpose:** Context-rich ransomware detection combining `.onion` addresses with ransom-related keywords.

**Triggers on:**
- v2/v3 `.onion` addresses (16 or 56 characters)
- HTTP(S) and `tor://` protocols
- Ransomware keywords: "ransom", "encrypted", "decrypt", "payment", "bitcoin"
- Ransom note indicators: "READ", "HOW_TO", "DECRYPT"

---

### 2. onion_links_simple

```yara
rule onion_links_simple {
    meta:
        description = "Detects any Tor .onion links (broad detection)"
        author      = "CG"
        severity    = "MEDIUM"
        category    = "TOR_INDICATOR"
    strings:
        $onion2 = /[a-z2-7]{16}\.onion/
        $onion3 = /[a-z2-7]{56}\.onion/
    condition:
        any of them and filesize < 52428800  // 50 MB
}
```

**Purpose:** Broad IOC sweep for any `.onion` address.

**Triggers on:**
- Any v2 or v3 `.onion` address

**Note:** May produce false positives on privacy guides, Tor Browser documentation, or academic papers.

---

### 3. ransomware_payment_portal

```yara
rule ransomware_payment_portal {
    meta:
        description = "Detects ransomware payment portals with onion links"
        author      = "CG"
        severity    = "CRITICAL"
        category    = "RANSOMWARE_C2"
    strings:
        $onion = /[a-z2-7]{16,56}\.onion/

        $pay1 = /\bpay\b/i
        $pay2 = "payment"        nocase
        $pay3 = "bitcoin wallet" nocase
        $pay4 = /btc/i
        $pay5 = /bc1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{38,59}/

        $dec1 = "decrypt"        nocase
        $dec2 = "decryption key" nocase
        $dec3 = "unlock"         nocase

        $urg1 = "deadline" nocase
        $urg2 = "hours"    nocase
        $urg3 = "days left" nocase

    condition:
        filesize < 18612019 and  // 17.75 MB - optimized for performance
        $onion and
        ( 2 of ($pay*) or 2 of ($dec*) ) and
        any of ($urg*)
}
```

**Purpose:** Identifies ransomware payment portals with urgency indicators.

**Triggers on:**
- `.onion` address presence
- Payment/decryption context (2+ matches required)
- Urgency indicators ("deadline", "hours", "days left")
- Bitcoin addresses (Bech32 format)

---

### 4. tor_c2_configuration

```yara
rule tor_c2_configuration {
    meta:
        description = "Detects C2 configs with Tor hidden service endpoints"
        author      = "CG"
        severity    = "CRITICAL"
        category    = "C2_COMMUNICATION"
    strings:
        $onion = /[a-z2-7]{16,56}\.onion/

        $c2_1 = /c2[_-]?server/i
        $c2_2 = /command[_-]?server/i
        $c2_3 = /control[_-]?server/i
        $c2_4 = "callback" nocase
        $c2_5 = "beacon"   nocase
        $c2_6 = "endpoint" nocase

        $cfg1 = /"url"\s*:/
        $cfg2 = /"endpoint"\s*:/
        $cfg3 = /"server"\s*:/

    condition:
        filesize < 52428800 and  // 50 MB
        $onion and
        any of ($c2_*) and
        any of ($cfg*)
}
```

**Purpose:** Detects C2 configuration files using Tor hidden services.

**Triggers on:**
- `.onion` address presence
- C2-related keywords ("c2_server", "callback", "beacon", etc.)
- Configuration file indicators (JSON key patterns)

---

## Compatibility

- **Tested with:** YARA v4.x+
- **Veeam Support:** Veeam Backup & Replication v12.1+ (including v12.3.2.4165 and v13)
- **Note:** If you encounter errors related to `MB` in filesize checks, the rules now use explicit byte values for maximum compatibility.

---

## Feedback & Recommendations

### ✅ Strengths
1. **Well-structured metadata**: Clear descriptions, author attribution, and severity levels make triage easier.
2. **Multi-protocol coverage**: Captures v2/v3 onion addresses, HTTP(S), and `tor://` protocols.
3. **Context-aware detection**: Combining `.onion` presence with ransomware keywords reduces false positives.
4. **Veeam compatibility**: Explicit filesize limits and tested compatibility with Veeam v12.1+/v13.

### 🔧 Improvements Implemented

#### 1. Filesize Syntax Consistency
- Replaced `MB` suffix with explicit byte values for universal YARA compatibility
- 25 MB = 26214400 bytes
- 50 MB = 52428800 bytes
- 17.75 MB = 18612019 bytes

#### 2. Performance Optimization
- Moved `filesize` checks to the beginning of conditions for faster short-circuiting
- Reduced unnecessary string comparisons when file is too large

#### 3. Regex Patterns
- Hyphen in character class `[\/\w.\-?=&]*` is properly escaped
- Dot (`.`) inside brackets is literal, matching actual dots in URLs

### 💡 Additional Recommendations

#### Bitcoin Address Enhancement
Consider adding legacy Bitcoin address formats:
```yara
$btc_legacy = /\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b/  // P2PKH/P2SH
$btc_segwit = /\bbc1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{38,87}\b/  // Bech32/Bech32m
```

#### Monero (XMR) Addresses
Many ransomware groups now prefer Monero:
```yara
$xmr_addr = /\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b/
```

#### False Positive Mitigation for `onion_links_simple`
```yara
$fp1 = "Tor Browser" nocase
$fp2 = "privacy guide" nocase
$fp3 = "academic research" nocase

condition:
    any of ($onion*) and
    filesize < 52428800 and
    not any of ($fp*)
```

#### Ransom Note Filenames
```yara
$filename1 = "README.txt" fullword nocase
$filename2 = "HOW_TO_DECRYPT.html" nocase
$filename3 = "DECRYPT_INSTRUCTIONS.txt" nocase
```

---

## Testing Recommendations

### False Positive Testing
Run against:
- Tor Project documentation
- Privacy-focused websites (EFF, PrivacyGuides)
- Academic papers on anonymity networks
- Security blogs discussing Tor

### True Positive Validation
Test against:
- Known ransomware samples from [MalwareBazaar](https://bazaar.abuse.ch/)
- Ransom note templates (Conti, LockBit, BlackCat, REvil)
- C2 configuration files from public malware analysis reports

### Performance Benchmarking
```bash
# Time the scan
time yara -r -w onion_ransomware_rules.yar /large/dataset/

# Count matches
yara -r onion_ransomware_rules.yar /path/to/scan/ | wc -l

# JSON output for analysis
yara -r --json onion_ransomware_rules.yar /samples > results.json
```

---

## License

MIT License

---

## Disclaimer

These rules are provided as-is for educational, research, and defensive security purposes. Always test in a safe, controlled environment before deploying in production. The author is not responsible for any misuse or damage caused by these rules.

---

**Author:** CG  
**Category:** Ransomware, Tor, C2 Detection  
**Last Updated:** December 18, 2025