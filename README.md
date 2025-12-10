# Autonomous AI Bug Bounty Agent

An expert-level, fully autonomous AI-powered web vulnerability scanner that uses Google's Gemini 2.5 Flash model to intelligently identify security vulnerabilities in web applications.

## Features

🤖 **Autonomous Scanning**
- Starts with basic reconnaissance (curl commands, DNS lookups, whois)
- Uses AI to analyze outputs and determine next steps
- Iteratively refines scanning strategy based on findings
- Stops when critical vulnerabilities are discovered

🔍 **Intelligent Vulnerability Detection**
- Recognizes indicators of common web vulnerabilities:
  - SQL Injection (SQLi)
  - Remote Code Execution (RCE)
  - Cross-Site Scripting (XSS)
  - Cross-Site Request Forgery (CSRF)
  - Server-Side Template Injection (SSTI)
  - XXE (XML External Entity)
  - SSRF (Server-Side Request Forgery)
  - Authentication Bypass
  - Path Traversal
  - Command Injection

📊 **Comprehensive Reporting**
- Generates detailed vulnerability reports in text format
- Includes vulnerability timeline
- Provides actionable remediation recommendations
- Timestamped scan history

## Installation

### Requirements
- Python 3.8+
- Google API Key (Gemini 2.5 Flash access required)
- curl, nmap, and other common security tools (optional but recommended)

### Setup

1. **Clone the repository**
```bash
git clone <repository-url>
cd bug-bounty-agent
```

2. **Create virtual environment**
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. **Install dependencies**
```bash
pip install -r requirements.txt
```

4. **Configure environment**
```bash
cp .env.example .env
# Edit .env and add your Google API Key
```

## Usage

### Basic Usage

```bash
python cli.py https://example.com
```

### With Custom Options

```bash
python cli.py https://example.com \
  --output my_report.txt \
  --max-iterations 20 \
  --timeout 15 \
  --verbose
```

### Command-line Arguments

| Argument | Short | Type | Description | Default |
|----------|-------|------|-------------|---------|
| `target` | - | str | Target website URL | Required |
| `--output` | `-o` | str | Output file path for report | Auto-generated |
| `--max-iterations` | `-i` | int | Maximum scanning iterations | 15 |
| `--timeout` | `-t` | int | Command timeout in seconds | 10 |
| `--verbose` | `-v` | flag | Enable verbose output | False |

### Python API Usage

```python
from bug_bounty_agent import BugBountyAgent

agent = BugBountyAgent()
agent.max_iterations = 20
report_file = agent.run("https://example.com")
print(f"Report saved to: {report_file}")
```

## How It Works

### Scanning Process

1. **URL Parsing & Validation**
   - Validates and normalizes the target URL
   - Extracts domain information

2. **Initial Reconnaissance**
   - Gathers HTTP headers
   - Performs DNS lookups
   - Retrieves WHOIS information
   - Tests basic connectivity

3. **AI-Driven Analysis Loop**
    - Sends reconnaissance data to Google Gemini 2.5 Flash
    - AI suggests next scanning steps based on context
    - Executes suggested commands
    - Analyzes outputs for vulnerability indicators

4. **Vulnerability Detection**
   - Scans command output for critical keywords
   - Identifies vulnerability patterns
   - Stops scanning when critical vulnerability is found

5. **Report Generation**
   - Creates comprehensive text report
   - Documents all findings
   - Provides remediation recommendations

### Iteration Cycle

```
Parse URL → Gather Initial Info → Loop:
  1. Send info to AI
  2. AI analyzes and suggests commands
  3. Execute suggested commands
  4. Check for vulnerabilities
  5. If critical found → Generate report & exit
  6. Otherwise → Continue (until max iterations)
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `GOOGLE_API_KEY` | Your Google API key for Gemini | Required |
| `MAX_ITERATIONS` | Maximum scanning iterations | 15 |
| `TIMEOUT` | Command execution timeout (seconds) | 10 |

### Example .env File

```
GOOGLE_API_KEY=your-google-api-key-here
MAX_ITERATIONS=15
TIMEOUT=10
```

## Output

### Report Location
Reports are saved to: `reports/scan_report_<domain>_<timestamp>.txt`

### Report Contents

- **Header Information**
  - Scan date and time
  - Target domain and URL
  - Total iterations performed
  - Vulnerabilities found count

- **Vulnerabilities Section**
  - Vulnerability type
  - Command that revealed it
  - Evidence/output excerpt
  - Severity level

- **Scan Timeline**
  - Commands executed
  - Results for each command
  - Timestamps

- **Recommendations**
  - Security improvements
  - Remediation steps
  - Best practices

## Example Report

```
================================================================================
AUTONOMOUS AI BUG BOUNTY SCAN REPORT
================================================================================

Scan Date: 2024-01-15 10:30:45
Target Domain: example.com
Target URL: https://example.com
Total Iterations: 5
Vulnerabilities Found: 2
Critical Status: YES

================================================================================
VULNERABILITIES DISCOVERED
================================================================================

[VULNERABILITY #1]
Iteration: 3
Type: sql injection
Command Used: curl -s 'https://example.com/search.php?q=test' OR 1=1'
Evidence:
Error in your SQL syntax near 'OR 1=1'...

[VULNERABILITY #2]
Iteration: 4
Type: remote code execution
Command Used: curl -X POST https://example.com/upload -F "file=@shell.php"
Evidence:
Warning: shell.php uploaded successfully...

================================================================================
RECOMMENDATIONS
================================================================================

⚠️ CRITICAL VULNERABILITIES DETECTED

Immediate Actions Required:
1. Isolate affected systems
2. Review and patch the identified vulnerability
3. Conduct security audit of related systems
4. Monitor for exploitation attempts
```

## Security & Ethics

⚠️ **Important**: This tool is designed for authorized security testing and bug bounty programs ONLY.

### Legal Considerations
- **Always obtain written authorization** before testing any system
- Use only on systems you own or have explicit permission to test
- Comply with all applicable laws and regulations
- Respect responsible disclosure practices

### Best Practices
- Test on staging/development environments first
- Limit scan scope to authorized domains
- Report vulnerabilities through proper channels
- Follow bug bounty program guidelines
- Document all findings appropriately

## Troubleshooting

### "GOOGLE_API_KEY not set"
- Ensure `.env` file exists in the project root
- Add your valid Google API key to `.env`
- Test with: `python -c "import os; from dotenv import load_dotenv; load_dotenv(); print(os.getenv('GOOGLE_API_KEY'))"`

### "Invalid URL format"
- Ensure URL includes protocol: `https://example.com` (not just `example.com`)
- Check for typos in domain name

### Commands timing out
- Increase `--timeout` value
- Check network connectivity
- Verify target is accessible

### AI not suggesting good commands
- Ensure Gemini 2.5 Flash model is available in your account
- Check Google API quotas and rate limits
- Verify API key has necessary permissions

## Advanced Usage

### Custom Scanning Strategy

You can extend the agent by subclassing:

```python
from bug_bounty_agent import BugBountyAgent

class CustomAgent(BugBountyAgent):
    def _generate_fallback_commands(self, iteration):
        # Add custom commands here
        return ["curl -s https://..."]

agent = CustomAgent()
agent.run("https://example.com")
```

### Batch Scanning

```bash
#!/bin/bash
for url in example.com target.com site.app; do
    python cli.py "$url" --max-iterations 10 --verbose
done
```

## Performance

- **Fast Initial Reconnaissance**: < 30 seconds
- **Per-Iteration Time**: 10-30 seconds (depending on AI response and command execution)
- **Typical Full Scan**: 2-5 minutes
- **Report Generation**: < 1 second

## Requirements

### System Dependencies (Optional)
For enhanced scanning, install security tools:

```bash
# Ubuntu/Debian
sudo apt-get install curl nmap nikto sqlmap

# macOS
brew install curl nmap nikto
```

## License

[Your License Here]

## Support & Contributing

For issues, questions, or contributions:
1. Check existing documentation
2. Review troubleshooting section
3. Submit detailed bug reports with:
   - Command used
   - Error messages
   - Environment details (OS, Python version)
   - Steps to reproduce

## Disclaimer

This tool is provided for authorized security testing and educational purposes. Users are responsible for ensuring they have proper authorization before testing any system. The authors are not liable for unauthorized use or damage caused by this tool.

---

**Created by**: Autonomous AI Bug Bounty Team
**Last Updated**: 2024-01-15
**Version**: 1.0
