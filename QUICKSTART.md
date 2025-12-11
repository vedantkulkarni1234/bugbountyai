# Quick Start Guide

## Installation (2 minutes)

### Step 1: Install Dependencies
```bash
pip install -r requirements.txt
```

#### Install Playwright Browsers (Recommended)
```bash
playwright install --with-deps chromium
```

### Step 2: Configure Google API Key
```bash
cp .env.example .env
```

Edit `.env` and add your Google API key:
```
GOOGLE_API_KEY=your-google-api-key-here
```

## Running Your First Scan (5 minutes)

### Option 1: Using CLI (Recommended)
```bash
python cli.py https://example.com
```

### Option 2: Using Python Script
```bash
python bug_bounty_agent.py https://example.com
```

### Option 3: Using Python API
```python
from bug_bounty_agent import BugBountyAgent

agent = BugBountyAgent()
report = agent.run("https://example.com")
print(f"Report saved to: {report}")
```

## Understanding the Output

### Console Output
```
[Iteration 1/15]
[*] Gathering domain information...
✓ Target URL: https://example.com
✓ Domain: example.com

[AI Analysis]
Based on the initial reconnaissance...
[Executing] curl -I -L -s https://example.com...
[Output] HTTP/1.1 200 OK...
```

### Report File
The scan generates a report in `reports/scan_report_<domain>_<timestamp>.txt`:
```
================================================================================
AUTONOMOUS AI BUG BOUNTY SCAN REPORT
================================================================================

Scan Date: 2024-01-15 10:30:45
Target Domain: example.com
...
```

## Common Commands

### Basic Scan
```bash
python cli.py https://example.com
```

### Detailed Scan with More Iterations
```bash
python cli.py https://example.com --max-iterations 20 --verbose
```

### Scan with Custom Report Location
```bash
python cli.py https://example.com -o /path/to/report.txt
```

### Increase Timeout for Slow Networks
```bash
python cli.py https://example.com --timeout 30
```

### Force Headless Browser Capture
```bash
python cli.py https://example.com --headless-mode on
```

## What to Expect

### Typical Scan Timeline
- **0-30 seconds**: Initial reconnaissance (DNS, headers, WHOIS)
- **30-120 seconds**: AI-guided vulnerability scanning (2-4 iterations)
- **120-300 seconds**: Deep vulnerability testing (if enabled)
- **300+ seconds**: Extended scanning for critical issues

### Success Indicators
- ✓ URL successfully parsed
- ✓ Domain information gathered
- ✓ Commands executed
- ✓ Report generated

### Critical Vulnerability Found
```
🚨 CRITICAL VULNERABILITY FOUND: sql injection
[Vulnerability #1]
Type: sql injection
Command Used: curl -s 'https://example.com/search?q=...
```

## Troubleshooting

### Problem: "GOOGLE_API_KEY not set"
**Solution**: Check that `.env` file exists and contains your API key
```bash
cat .env | grep GOOGLE_API_KEY
```

### Problem: "Invalid URL format"
**Solution**: Ensure URL includes https://
```bash
# Wrong
python cli.py example.com

# Correct
python cli.py https://example.com
```

### Problem: Scan takes too long
**Solution**: Reduce max iterations
```bash
python cli.py https://example.com --max-iterations 5
```

### Problem: "Connection timeout"
**Solution**: Increase timeout value
```bash
python cli.py https://example.com --timeout 30
```

### Problem: "Playwright is not installed"
**Solution**:
```bash
pip install -r requirements.txt
playwright install --with-deps chromium
export ENABLE_HEADLESS_BROWSER=false  # optional if you want to skip it
```

## Next Steps

1. **Review the Report**
   ```bash
   cat reports/scan_report_*.txt
   ```

2. **Understand Findings**
   - Read vulnerability descriptions
   - Review recommended actions
   - Check evidence in the report

3. **Take Action**
   - If vulnerabilities found: Report them appropriately
   - If no vulnerabilities: Continue monitoring with periodic scans
   - Keep detailed records of all findings

4. **Learn More**
   - Read [README.md](README.md) for detailed documentation
   - Check [ARCHITECTURE.md](ARCHITECTURE.md) for technical details
   - Review example reports in `reports/` directory

## API Key Setup

### Getting Your Google API Key

1. Visit https://aistudio.google.com
2. Sign up or log in
3. Go to API keys section
4. Create a new API key
5. Copy the key to your `.env` file

### Verify Your Setup
```bash
python -c "
import os
from dotenv import load_dotenv
load_dotenv()
key = os.getenv('GOOGLE_API_KEY')
if key:
    print('✓ API Key found!')
    print(f'  Key starts with: {key[:15]}...')
else:
    print('❌ API Key not found!')
"
```

## Performance Tips

### For Faster Scans
- Reduce `--max-iterations` to 5-10
- Use `--timeout 5` for responsive servers
- Target specific paths instead of whole domain

### For Thorough Scans
- Increase `--max-iterations` to 20+
- Use `--timeout 30` for comprehensive analysis
- Run multiple scans with different strategies

## Best Practices

✓ Always scan on staging/test environments first
✓ Keep API rate limits in mind (rate limiting available)
✓ Save reports for audit trails
✓ Follow responsible disclosure
✓ Get written authorization before testing
✓ Document findings properly

## Need Help?

1. Check [README.md](README.md) - Full documentation
2. Review error messages carefully
3. Check the generated report for more details
4. Enable `--verbose` flag for more information

## Example Workflows

### Simple Security Check
```bash
python cli.py https://example.com --max-iterations 5
```

### Comprehensive Audit
```bash
python cli.py https://example.com --max-iterations 20 --verbose
```

### Quick Verification
```bash
python cli.py https://example.com --timeout 5 --max-iterations 3
```

---

**Ready to start?** Run your first scan:
```bash
python cli.py https://example.com
```
