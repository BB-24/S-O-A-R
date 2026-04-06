# Malware Analysis Automation Pipeline

A production-quality Python framework for automating malware analysis by integrating multiple external sandbox APIs, normalizing results, and generating comprehensive intelligence reports.

## Features

- **Multi-Sandbox Integration**: Parallel submission to Hybrid Analysis and VirusTotal
- **Unified Schema**: Normalizes responses from different APIs into a canonical data model
- **Report Merging**: Intelligently combines results from multiple sources with deduplication
- **IOC Intelligence**: Extracts and deduplicated Indicators of Compromise
- **MITRE ATT&CK Mapping**: Correlates observed behaviors with MITRE techniques
- **Professional Reports**: Generates beautifulbootstrap-styled HTML and structured JSON reports
- **Resilient**: Handles API failures, timeouts, and network errors gracefully
- **Extensible**: Plugin-style architecture for adding new sandbox integrations
- **Proper Logging**: Clean, structured logging for debugging and monitoring

## Architecture

```
ENTRY LAYER
└── analyzer.py (CLI orchestrator)

API LAYER
├── clients/
│   ├── base.py (abstract interface)
│   ├── hybrid_analysis.py (HybridAnalysisClient)
│   └── virustotal.py (VirusTotalClient)

NORMALIZATION LAYER
├── normalizers/
│   ├── base.py (BaseNormalizer)
│   ├── hybrid_analysis.py
│   └── virustotal.py

CORE SCHEMA
└── schema.py (UnifiedReport, IOC, MergedReport, etc.)

MERGER & CORRELATION
├── merger.py (combines multiple reports)
└── correlator/
    ├── correlation_engine.py (enrichment)
    └── ioc_extractor.py (IOC extraction)

REPORTING
├── report_generator/
│   ├── html_generator.py (Bootstrap HTML reports)
│   └── json_export.py (Structured JSON)
    └── templates/ (HTML templates)

ARTIFACTS
└── artifacts/{SHA256}/ (raw API responses, final reports)
```

## Installation

### 1. Clone/Setup Project

```bash
cd SOAR
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Get API Keys

- **Hybrid Analysis**: https://hybrid-analysis.com/api
- **VirusTotal**: https://www.virustotal.com/gui/my-apikey

### 4. Configure Environment

```bash
cp .env.example .env
# Edit .env and add your API keys
nano .env
```

### 5. Verify Setup

```bash
python -c "from analyzer import MalwareAnalyzer; MalwareAnalyzer(); print('✓ Setup OK')"
```

## Usage

### Basic Analysis

```bash
python analyzer.py samples/malware.exe
```

### Custom Output Directory

```bash
python analyzer.py samples/malware.exe --output results/
```

### Verbose Logging

```bash
python analyzer.py samples/malware.exe --verbose
```

### Advanced Example

```bash
python analyzer.py samples/malware.exe \
  --output artifacts/analysis_2024 \
  --verbose
```

## Output

Analysis generates two reports in the output directory:

### HTML Report (`report.html`)
- Executive summary with risk score
- File hashes (MD5, SHA1, SHA256)
- Verdict from all sandbox sources
- IOC table (IPs, domains, URLs, hashes)
- Network activity timeline
- Process execution details
- MITRE ATT&CK technique mapping
- AV engine detections
- Beautiful Bootstrap styling

### JSON Report (`report.json`)
Structured machine-readable data with:
- File metadata
- Verdict analysis by source
- Risk assessment
- Complete IOC list
- Network activity details
- Process tree
- File operations
- MITRE techniques
- Consolidated metadata

## Project Structure

```
SOAR/
├── analyzer.py                    # Main entry point
├── schema.py                      # Unified data models
├── merger.py                      # Report merging logic
│
├── clients/                       # Sandbox API clients
│   ├── base.py
│   ├── hybrid_analysis.py
│   └── virustotal.py
│
├── normalizers/                   # API response normalization
│   ├── base.py
│   ├── hybrid_analysis.py
│   └── virustotal.py
│
├── correlator/                    # Intelligence correlation
│   ├── correlation_engine.py      # Engine & MITRE mapping
│   └── ioc_extractor.py           # IOC extraction
│
├── report_generator/              # Report generation
│   ├── html_generator.py          # HTML reports
│   └── json_export.py             # JSON export
│
├── artifacts/                     # Analysis output
│├── requirements.txt              # Dependencies
├── .env.example                   # Configuration template
└── README.md                      # This file
```

## Key Classes & Components

### MalwareAnalyzer (analyzer.py)
Main orchestrator that:
- Initializes all sandbox clients
- Submits files in parallel
- Merges reports
- Generates output

```python
analyzer = MalwareAnalyzer()
output_files = analyzer.analyze("samples/malware.exe", "results/")
```

### UnifiedReport (schema.py)
Canonical report format containing:
- File metadata (hashes, size, type)
- Analysis results (verdict, detections)
- Behavioral data (processes, network, files)
- IOCs and MITRE techniques
- Risk assessment

### MergedReport (schema.py)
Consolidated report from multiple sources:
- Deduplicates IOCs
- Merges network activity
- Consensus verdict voting
- Weighted risk scoring

### Normalizers
Convert sandbox-specific formats to `UnifiedReport`:
- `HybridAnalysisNormalizer`: Converts Hybrid Analysis API responses
- `VirusTotalNormalizer`: Converts VirusTotal API responses

### ReportMerger (merger.py)
Intelligently combines multiple reports:
- IOC deduplication (by type+value)
- Process merging (by name+PID)
- Network activity merging
- Consensus verdict determination
- Weighted risk score calculation

### CorrelationEngine (correlator/correlation_engine.py)
Enriches merged reports:
- Extracts additional IOCs from behavior
- Maps processes to MITRE ATT&CK techniques
- Performs threat intelligence enrichment
- Builds attack narratives

## Data Models

### IOC (Indicator of Compromise)
```python
IOC(
    ioc_type=IOCType.DOMAIN,  # enum: IP, DOMAIN, URL, MD5,SHA1, SHA256, etc.
    value="malicious.com",
    source=[SandboxSource.HYBRID_ANALYSIS, SandboxSource.VIRUSTOTAL],
    confidence=0.95,           # 0.0 - 1.0
    metadata={}
)
```

### NetworkActivity
```python
NetworkActivity(
    protocol="https",          # tcp, udp, dns, http, https
    direction="outbound",
    destination_ip="192.0.2.1",
    destination_port=443,
    domain="c2.malicious.com",
    url="https://c2.malicious.com/beacon",
    user_agent="Mozilla/5.0..."
)
```

### Process
```python
Process(
    name="malware.exe",
    pid=1234,
    parent_pid=456,
    command_line="malware.exe /c evil.ps1",
    user="admin"
)
```

## Configuration

### Environment Variables (.env)

```bash
# API Keys (required)
HYBRID_ANALYSIS_API_KEY=xxx
VIRUSTOTAL_API_KEY=yyy

# Optional Settings
API_TIMEOUT=30              # seconds
MAX_WORKERS=3               # parallel submissions
LOG_LEVEL=INFO
OUTPUT_DIR=artifacts
```

## Error Handling

The pipeline is designed to be resilient:

- **Partial Failures**: If one sandbox fails, analysis continues with others
- **Retry Logic**: Automatic retries with exponential backoff
- **Rate Limiting**: Handles API rate limits gracefully
- **Timeouts**: Configurable timeouts with warnings
- **Graceful Degradation**: Works with partial data

```python
try:
    analyzer.analyze("malware.exe")
except FileNotFoundError:
    print("File not found")
except RuntimeError as e:
    print(f"Analysis failed: {e}")
```

## Extending the Pipeline

### Add a New Sandbox

1. Create new client in `clients/newsandbox.py`:

```python
from clients.base import BaseSandboxClient

class NewSandboxClient(BaseSandboxClient):
    def submit_file(self, file_path):
        # Implementation
        pass
    # ... implement other methods
```

2. Create normalizer in `normalizers/newsandbox.py`:

```python
from normalizers.base import BaseNormalizer

class NewSandboxNormalizer(BaseNormalizer):
    def normalize(self, raw_response):
        # Convert to UnifiedReport
        pass
```

3. Register in `analyzer.py`:

```python
from clients.newsandbox import NewSandboxClient
# In _initialize_clients():
if newsandbox_key:
    self.clients[SandboxSource.NEWSANDBOX] = NewSandboxClient(...)
```

## Development

### Running Tests

```bash
pytest tests/ -v --cov
```

### Code Quality

```bash
# Format code
black .

# Lint
flake8 .

# Type checking
mypy .

# Security scan
bandit -r .
```

## Performance

- **Parallel Submissions**: Uses ThreadPoolExecutor for concurrent API calls
- **Typical Analysis Time**: 2-5 minutes (depends on sandbox queue)
- **Memory Usage**: ~50-100MB per analysis
- **Report Generation**: <1 second

## Troubleshooting

### No API Keys Found
```
RuntimeError: No sandbox clients initialized. Check API keys in .env
```
**Solution**: Ensure `.env` file exists and contains valid API keys.

### Analysis Timeout
```
WARNING: {sandbox} analysis timeout
```
**Solution**: Increase `API_TIMEOUT` in `.env` or use `--verbose` to debug.

### Network Errors
```
RequestException: Connection refused
```
**Solution**: Check internet connection and API endpoint availability.

## Security Considerations

- **API Key Storage**: Never commit `.env` with real keys
- **Input Validation**: File paths are validated before submission
- **Output Sanitization**: Reports are HTML-escaped to prevent XSS
- **Logging**: Sensitive data is not logged
- **Rate Limiting**: Respects API rate limits

## Limitations & Caveats

- No actual sandbox environment (uses external APIs only)
- Dependent on third-party sandbox availability
- Analysis quality varies by sandbox sophistication
- Large files may not be supported by all sandboxes
- Real-time API failures affect analysis

## Future Enhancements

- [ ] Caching layer for duplicate file hashes
- [ ] Machine learning-based risk scoring
- [ ] Real-time alerting integration
- [ ] Database backend for historical analysis
- [ ] Web UI dashboard
- [ ] CLI configuration file support
- [ ] Batch analysis mode
- [ ] Integration with SIEM platforms

## License

This project is provided as-is for security research and analysis purposes.

## Contact & Support

For issues or questions, refer to the architecture documentation and code comments within each module.

---

**Built with**: Python 3.10+, Requests, Jinja2, Bootstrap 5, JSON

**Version**: 1.0.0  
**Last Updated**: 2024
