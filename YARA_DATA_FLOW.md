# YARA IOC Extraction - Data Flow Diagram

## Complete Pipeline with YARA Integration

```
┌─────────────────────────────────────────────────────────────────────┐
│                         MALWARE SAMPLE                              │
│                      (Binary File Upload)                           │
└──────────────────────────┬──────────────────────────────────────────┘
                           │
        ┌──────────────────┴──────────────────┐
        │                                     │
        ▼                                     ▼
   ┌────────────────┐          ┌──────────────────────┐
   │ Hybrid Analysis│          │   VirusTotal API     │
   │   (Sandbox)    │          │    (Sandbox)         │
   └────────┬───────┘          └──────────┬───────────┘
            │                             │
            └──────────────┬──────────────┘
                           │
                           ▼
        ┌──────────────────────────────────────┐
        │    Report Normalization              │
        │  • HA Normalizer                     │
        │  • VT Normalizer                     │
        └──────────────┬───────────────────────┘
                       │
                       ▼
        ┌──────────────────────────────────────┐
        │    Report Merger                     │
        │  • Deduplicate IOCs                  │
        │  • Merge Detection Data              │
        │  • Consensus Verdict                 │
        └──────────────┬───────────────────────┘
                       │
                       ▼
   ╔═══════════════════════════════════════════════════════════════╗
   ║         CORRELATION ENGINE (New YARA Integration)             ║
   ║                                                               ║
   ║  ┌──────────────────────┐   ┌──────────────────────┐        ║
   ║  │   YARA Scanner       │   │ Behavioral Analysis  │        ║
   ║  │ ┌────────────────┐   │   │ ┌────────────────┐   │        ║
   ║  │ │Rule Compilation│   │   │ │Network Activity│   │        ║
   ║  │ │(Load .yar)     │   │   │ │File Operations │   │        ║
   ║  │ └────────┬───────┘   │   │ │Registry Mods   │   │        ║
   ║  │          │           │   │ └────────┬───────┘   │        ║
   ║  │ ┌────────▼────────┐  │   │          │           │        ║
   ║  │ │File Scanning    │  │   │ ┌────────▼───────┐   │        ║
   ║  │ │(Memory/String)  │  │   │ │IOC Extraction  │   │        ║
   ║  │ └────────┬────────┘  │   │ │(DNS/IP/Files) │   │        ║
   ║  │          │           │   │ └────────┬───────┘   │        ║
   ║  │ ┌────────▼────────────────────────┐ │           │        ║
   ║  │ │  IOC Classification & Extraction│ │           │        ║
   ║  │ │  URL, IP, Domain, Hash, Behavior│ │           │        ║
   ║  │ └────────┬───────────────────┬────┘ │           │        ║
   ║  │          │                   │      │           │        ║
   ║  └──────────┼───────────────────┼──────┘           │        ║
   ║             │                   │                   │        ║
   ║             └───────┬───────────┘                   │        ║
   ║                     │                               │        ║
   ║             ┌───────▼──────────┐                   │        ║
   ║             │  IOC Merging &   │                   │        ║
   ║             │ Deduplication    │                   │        ║
   ║             │                  │                   │        ║
   ║             │ Sources:         │                   │        ║
   ║             │ • YARA           │                   │        ║
   ║             │ • Behavioral     │                   │        ║
   ║             └───────┬──────────┘                   │        ║
   ║                     │                               │        ║
   ║  ┌──────────────────▼──────────────┐  ┌──────────▼──────┐ ║
   ║  │  MITRE ATT&CK Mapping           │  │ Threat Intel    │ ║
   ║  │  • Network Patterns → T1071     │  │ Enrichment      │ ║
   ║  │  • File Operations → T1112      │  │                 │ ║
   ║  │  • Registry Mods → T1547        │  │ Confidence      │ ║
   ║  │                                 │  │ Scoring         │ ║
   ║  └──────────────┬──────────────────┘  └────────┬────────┘ ║
   ║                 │                             │            ║
   ║                 └──────────────┬──────────────┘            ║
   ║                                │                            ║
   ║                        ┌───────▼────────┐                 ║
   ║                        │ Enriched Report│                 ║
   ║                        │ • IOCs (n)     │                 ║
   ║                        │ • Techniques   │                 ║
   ║                        │ • Verdict      │                 ║
   ║                        └────────┬───────┘                 ║
   ║                                 │                          ║
   ╚═════════════════════════════════╪══════════════════════════╝
                                     │
                                     ▼
        ┌──────────────────────────────────────┐
        │    Report Generation                 │
        │  • HTML Dashboard                    │
        │  • JSON Export                       │
        │  • PDF Summary (optional)            │
        └──────────────┬───────────────────────┘
                       │
        ┌──────────────┴───────────┬──────────┐
        │                          │          │
        ▼                          ▼          ▼
   ┌─────────────┐          ┌──────────┐  ┌─────────┐
   │HTML Report  │          │JSON File │  │ Logs    │
   │ • IOCs      │          │ • Data   │  │ Output  │
   │ • Network   │          │ • Metrics│  │         │
   │ • Processes │          │          │  │         │
   │ • MITRE     │          └──────────┘  └─────────┘
   └─────────────┘
```

## IOC Flow Detail

```
┌──────────────────────────────────────┐
│     YARA Scan Results                │
│  Rule: Suspicious_Network_Comms      │
│  Matches:                            │
│    $url = "http://c2.malware.com"    │
│    $ip = "192.168.1.100"             │
│    $domain = "evil.com"              │
└──────────────┬───────────────────────┘
               │
               ▼
  ┌────────────────────────────────────┐
  │  IOC Classification Engine         │
  │                                    │
  │  Input: Matched strings            │
  │  ├─ Process identifier ($url)      │
  │  ├─ Analyze string value           │
  │  └─ Match against patterns         │
  │                                    │
  │  Output: Typed IOCs                │
  └────────────┬─────────────────────┘
               │
       ┌───────┴─────────┬──────────┐
       │                 │          │
       ▼                 ▼          ▼
    URL IOC         IP IOC       DOMAIN IOC
  ┌─────────┐  ┌──────────┐  ┌────────────┐
  │ Type:   │  │ Type:    │  │ Type:      │
  │ URL     │  │ IP_ADDR  │  │ DOMAIN     │
  │         │  │          │  │            │
  │ Value:  │  │ Value:   │  │ Value:     │
  │ http:// │  │ 192.168  │  │ evil.com   │
  │ c2.com  │  │ 1.100    │  │            │
  │         │  │          │  │            │
  │ Conf:   │  │ Conf:    │  │ Conf:      │
  │ 0.85    │  │ 0.85     │  │ 0.85       │
  │         │  │          │  │            │
  │ Source: │  │ Source:  │  │ Source:    │
  │ YARA    │  │ YARA     │  │ YARA       │
  └────┬────┘  └────┬─────┘  └─────┬──────┘
       │            │              │
       └────────────┴──────────────┘
                    │
                    ▼
         ┌──────────────────────────┐
         │   Merge with Behavioral  │
         │        IOCs              │
         │                          │
         │ Input: All IOCs from:    │
         │  • YARA scanning         │
         │  • Network behavior      │
         │  • File operations       │
         │  • Registry changes      │
         │                          │
         │ Process:                 │
         │  • Deduplication         │
         │  • Source merging        │
         │  • Confidence scoring    │
         │                          │
         │ Output: Unified IOC set  │
         └────────────┬─────────────┘
                      │
                      ▼
         ┌──────────────────────────┐
         │   Display in Dashboard   │
         │   ┌──────────────────┐   │
         │   │ Type │ Value │ SC│   │
         │   ├──────────────────┤   │
         │   │ URL  │ http://   │87 │   │
         │   │ IP   │ 192.168   │85 │   │
         │   │ DOM  │ evil.com  │85 │   │
         │   │      │ YARA:     │   │   │
         │   │      │ Susp.Net  │95 │   │
         │   └──────────────────┘   │
         └──────────────────────────┘
```

## Example: Complete IOC Lifecycle

```
Step 1: YARA Rule Matches
├─ Rule: Suspicious_Network_Communications
├─ Match: String $domain = "malware.net"
└─ Location: Offset 0x4500 in sample

Step 2: Classification
├─ Identifier: $domain
├─ Value: "malware.net"
├─ Pattern Match: Matches domain regex
└─ Type: DOMAIN

Step 3: Metadata Assignment
├─ Confidence: 0.85
├─ Source: BEHAVIORAL
├─ YARA Rule: Suspicious_Network_Communications
├─ YARA Offset: 0x4500
├─ YARA Tags: [network, c2, behavioral]
└─ Extraction Method: yara_string

Step 4: Deduplication
├─ Check against existing IOCs
├─ If matching domain exists:
│  └─ Merge sources
├─ If new domain:
│  └─ Add to IOC list
└─ Result: single unique IOC

Step 5: Display
├─ Dashboard shows:
│  ├─ Type: DOMAIN
│  ├─ Value: malware.net
│  ├─ Confidence: 85%
│  ├─ YARA Rule: Suspicious_Network_Communications
│  └─ Source: BEHAVIORAL
└─ User can export to JSON/CSV
```

## Multiple Source Merging

```
        NETWORK ACTIVITY           YARA MATCHES
        ┌────────────────┐        ┌────────────────┐
        │ IPs detected   │        │ Rule matches   │
        │ - 10.0.0.5     │        │ - Domain: c2.com
        │ - 10.0.0.6     │        │ - Hash: abc123..
        │                │        │ - IP: 10.0.0.5
        │ Domains:       │        │                │
        │ - google.com   │        │ Tags:          │
        │ - example.com  │        │ - malware      │
        └────────┬───────┘        │ - c2           │
                 │                └────────┬───────┘
                 │                        │
                 └────────────┬───────────┘
                              │
                              ▼
                ┌─────────────────────────┐
                │   Consolidated IOCs     │
                │ ┌─────────────────────┐ │
                │ │ IP: 10.0.0.5        │ │
                │ │ Sources:            │ │
                │ │  - BEHAVIORAL (net) │ │
                │ │  - BEHAVIORAL (yara)│ │
                │ │ Confidence: 0.90    │ │
                │ └─────────────────────┘ │
                │                         │
                │ ┌─────────────────────┐ │
                │ │ Domain: example.com │ │
                │ │ Sources:            │ │
                │ │  - BEHAVIORAL (net) │ │
                │ │ Confidence: 0.85    │ │
                │ └─────────────────────┘ │
                │                         │
                │ ┌─────────────────────┐ │
                │ │ Domain: c2.com      │ │
                │ │ Sources:            │ │
                │ │  - BEHAVIORAL (yara)│ │
                │ │ Confidence: 0.85    │ │
                │ └─────────────────────┘ │
                └─────────────────────────┘
```

## Integration Checkpoints

```
Analyzer Started
       ↓
[✓] Load Config
    └─ YARA_RULES_PATH=yara_rules
       ↓
[✓] Initialize CorrelationEngine
    └─ YARA Scanner initialized
       ├─ Rules compiled
       └─ Ready for scanning
       ↓
[✓] Sandbox Analysis Complete
    └─ Behavioral data collected
       ├─ Network activities
       ├─ File operations
       └─ Registry modifications
       ↓
[✓] Report Merging
    └─ Data consolidated
       ↓
[✓] Correlation Analysis STARTS
    ├─ YARA scanning phase
    │  ├─ Sample scanned
    │  ├─ Matches found: n
    │  └─ IOCs extracted: m
    │
    ├─ Behavioral analysis phase
    │  ├─ Network IOCs: x
    │  ├─ File IOCs: y
    │  └─ Registry IOCs: z
    │
    ├─ Deduplication phase
    │  ├─ Total unique IOCs: n+m+x+y+z
    │  └─ Merged sources
    │
    └─ MITRE mapping
       └─ Techniques mapped: p
       ↓
[✓] Report Generation
    ├─ HTML with IOC tables
    ├─ JSON with metadata
    └─ Dashboard ready
       ↓
[✓] Analysis Complete
    └─ Results in artifacts/
```

---

**This visual flow shows how YARA seamlessly integrates into every step of your analysis pipeline!**
