# YARA Integration Setup Guide

## Overview

This project now integrates YARA (Yet Another Regex Engine) for malware detection and pattern-based IOC extraction. YARA rules scan samples and behavioral data to detect malware families and extract indicators of compromise automatically.

## Quick Start

### 1. Obtain YARA Rules

You can use YARA rules from popular public repositories:

#### Option A: Yara-Rules Repository
```bash
# Clone the official YARA-Rules repository
git clone https://github.com/Yara-Rules/rules.git yara_rules
```

#### Option B: Malware-Traffic-Analysis Rules
```bash
# Clone Malware Traffic Analysis YARA rules
git clone https://github.com/malware-traffic-analysis.net/yara_rules.git yara_rules
```

#### Option C: Custom Rules
Create your own `.yar` or `.yara` files in a `yara_rules` directory.

### 2. Configure YARA_RULES_PATH

Edit your `.env` file and set the YARA_RULES_PATH:

```env
# Set to your YARA rules directory
YARA_RULES_PATH=yara_rules
# or absolute path
# YARA_RULES_PATH=C:\full\path\to\yara_rules
```

### 3. Verify Installation

```bash
# Activate virtual environment
source venv/Scripts/activate  # On Windows
# or
& "venv\Scripts\Activate.ps1" # PowerShell

# Test YARA import
python -c "import yara; print('YARA installed successfully')"
```

## How It Works

### Integration Flow

1. **Sample Scanning**: YARA scans the malware sample against all configured rules
2. **IOC Extraction**: Matched rules extract indicators from:
   - YARA string matches (URLs, IPs, domains, file hashes)
   - Rule metadata and tags
   - Behavioral pattern names
3. **Dashboard Display**: Extracted IOCs are displayed in the HTML report

### IOC Types Extracted from YARA

| YARA Element | IOC Type | Confidence |
|---|---|---|
| String marked `$url` | URL | 0.85 |
| String marked `$ip` | IP Address | 0.85 |
| String marked `$domain` | Domain | 0.85 |
| String marked `$hash` | MD5/SHA1/SHA256 | 0.85 |
| Rule name match | Process Behavior | 0.95 |
| String literals in rules | Domain/URL/IP | 0.85 |

## YARA Rule Structure

### Recommended Rule Format

```yara
rule Trojan_Generic_Behavior
{
    meta:
        description = "Detects generic trojan behavior patterns"
        author = "Security Team"
        date = "2025-01-01"
        severity = "high"
        family = "Trojan.Generic"
    
    strings:
        $url_c2 = "hxxp://malicious-c2.com" nocase
        $domain_c2 = "command-and-control.net" nocase
        $ip = /\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9]{1,2})\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9]{1,2})\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9]{1,2})\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9]{1,2})\b/ wide
        $registry_run = "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" nocase
    
    condition:
        2 of them
}
```

## IOCs in HTML Dashboard

IOCs extracted from YARA rules appear in the report with:

- **Type**: Malware family, domain, IP, etc.
- **Value**: The actual IOC (domain name, IP address, etc.)
- **Confidence**: 0.85-0.95 (YARA-based confidence)
- **Source**: BEHAVIORAL (from YARA rules)
- **Metadata**: 
  - `yara_rule`: Name of the YARA rule that matched
  - `yara_tags`: Tags from the YARA rule
  - `yara_meta`: Metadata from the YARA rule (author, date, family, etc.)

### Example Report Display

The HTML dashboard will show a table like:

| Type | Value | Confidence | YARA Rule | Tags |
|---|---|---|---|---|
| PROCESS_BEHAVIOR | Trojan.Generic | 95% | Trojan_Generic_Behavior | trojan, malware |
| URL | hxxp://c2-server.net | 85% | C2_Communication | c2, network |
| IP_ADDRESS | 192.168.1.100 | 85% | C2_Communication | c2, network |

## Performance Considerations

- **Rule Compilation**: First scan compiles all rules (takes a few seconds)
- **Large Samples**: YARA scanning is fast (<1s for most files)
- **Rule Set Size**: Larger rule sets take longer to scan
  - Small (100 rules): <100ms
  - Medium (1000 rules): <500ms
  - Large (10000+ rules): 1-5s

### Optimization Tips

1. **Use Modular Rules**: Organize rules in subdirectories by category
2. **Include/Exclude Rules**: Disable rules you don't need
3. **Optimize Rule Conditions**: Use specific conditions instead of generic ones
4. **Regular Updates**: Keep rules updated for latest malware families

## Troubleshooting

### Issue: "No YARA rules path found"

**Solution**: Set `YARA_RULES_PATH` in `.env` file

```env
YARA_RULES_PATH=yara_rules
```

### Issue: "YARA rules not configured"

**Solution**: Verify the directory exists and contains `.yar`/`.yara` files

```bash
ls -la yara_rules/
# Should show .yar or .yara files
```

### Issue: "Failed to compile YARA rules"

**Cause**: Syntax error in YARA rules  
**Solution**: Validate rules with YARA command-line:

```bash
yara -d yara_rules/ dummy_file
```

### Issue: No IOCs in report from YARA

**Possible causes**:
1. Rules don't match the sample
2. String identifiers not recognized (must start with `$`)
3. Rule conditions evaluate to false

**Solution**: Add debug logging and test rules individually

## Customization

### Adding Custom Rules

1. Create a `.yar` file in your `yara_rules` directory:

```yara
rule Custom_Trojan
{
    meta:
        description = "My custom detection"
        author = "Your Name"
        severity = "high"
    
    strings:
        $cmd = "cmd.exe" nocase
        $powershell = "powershell" nocase
        $registry = "HKEY_LOCAL_MACHINE" nocase
    
    condition:
        2 of them
}
```

2. Restart the analysis pipeline (rules are loaded on startup)

### Modifying IOC Classification

Edit `correlator/yara_scanner.py` in the `_classify_yara_string()` method to customize how YARA strings are classified as IOCs:

```python
def _classify_yara_string(self, identifier: str, value: str) -> Optional[IOCType]:
    # Add custom classification logic here
    if 'custom_pattern' in identifier:
        return IOCType.URL  # or other IOCType
    # ... rest of method
```

## Best Practices

1. **Organize Rules**: Group related rules by malware family or behavior
2. **Add Metadata**: Include author, date, severity in all rules
3. **Test Rules**: Validate before adding to production
4. **Update Regularly**: Use latest YARA rules database
5. **Document Rules**: Add descriptions and references
6. **Minimize False Positives**: Use specific conditions
7. **Monitor Performance**: Check scan times with rule set size

## Integration with Other Components

- **Correlation Engine**: YARA IOCs are merged with behavioral IOCs
- **Report Generator**: IOCs appear in HTML/JSON reports
- **IOC Deduplication**: Duplicate IOCs across sources are merged
- **Confidence Scoring**: YARA matches scored at 0.85-0.95

## Example Workflow

1. Sample submitted for analysis
2. Hybrid Analysis and VirusTotal analyze sample
3. Correlation engine extracts behavioral IOCs
4. YARA scanner runs against:
   - Sample binary
   - Detection/metadata text
5. All IOCs merged and deduplicated
6. Report generated with IOCs from all sources
7. YARA matches displayed with rule name and confidence

## Additional Resources

- [YARA Documentation](https://yara.readthedocs.io/)
- [Yara-Rules Repository](https://github.com/Yara-Rules/rules)
- [YARA GitHub](https://github.com/VirusTotal/yara)
- [Writing YARA Rules](https://yara.readthedocs.io/en/stable/writingrules.html)

## Uninstalling YARA

If you need to disable YARA scanning:

1. Clear `YARA_RULES_PATH` in `.env`:
   ```env
   YARA_RULES_PATH=
   ```

2. Or comment out the import in `correlator/correlation_engine.py`:
   ```python
   # from correlator.yara_scanner import YARAScanner
   ```

The pipeline will continue to work with behavioral IOC extraction only.
