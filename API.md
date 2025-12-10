# API Documentation

## BugBountyAgent Class

Main class for performing autonomous vulnerability scanning.

### Constructor

```python
agent = BugBountyAgent()
```

**Parameters**: None

**Raises**:
- `ValueError`: If `OPENAI_API_KEY` is not set

**Attributes**:
- `api_key` (str): OpenAI API key
- `client` (OpenAI): OpenAI client instance
- `max_iterations` (int): Maximum scanning iterations (default: 15)
- `timeout` (int): Command timeout in seconds (default: 10)
- `target_url` (str): Target website URL
- `domain` (str): Extracted domain name
- `vulnerabilities` (list): List of found vulnerabilities
- `scan_history` (list): Scan history entries
- `critical_found` (bool): Whether critical vulnerability was found

### Methods

#### `parse_url(url: str) -> bool`

Validate and parse a target URL.

**Parameters**:
- `url` (str): Target URL (with or without protocol)

**Returns**:
- `bool`: True if valid, False otherwise

**Example**:
```python
agent = BugBountyAgent()
if agent.parse_url("https://example.com"):
    print(f"Target domain: {agent.domain}")
```

#### `get_domain_info() -> Dict[str, str]`

Gather initial domain reconnaissance information.

**Returns**:
- `Dict[str, str]`: Dictionary containing:
  - `http_headers`: HTTP response headers
  - `dns_info`: DNS lookup results
  - `whois_info`: WHOIS information
  - `https_status`: HTTPS status code

**Example**:
```python
info = agent.get_domain_info()
print(info['http_headers'])
```

#### `execute_command(command: str) -> Tuple[bool, str]`

Execute a shell command safely.

**Parameters**:
- `command` (str): Command to execute

**Returns**:
- `Tuple[bool, str]`: (success, output) tuple

**Example**:
```python
success, output = agent.execute_command("curl -I https://example.com")
if success:
    print(output)
```

#### `analyze_with_ai(context: str, instruction: str) -> str`

Use OpenAI to analyze information and determine next steps.

**Parameters**:
- `context` (str): Reconnaissance data context
- `instruction` (str): Analysis instruction

**Returns**:
- `str`: AI response with suggested commands

**Example**:
```python
response = agent.analyze_with_ai(
    context="HTTP 200, Server: Apache",
    instruction="Suggest vulnerability testing commands"
)
print(response)
```

#### `check_for_vulnerabilities(output: str) -> Tuple[bool, str]`

Check if output indicates a critical vulnerability.

**Parameters**:
- `output` (str): Command output to analyze

**Returns**:
- `Tuple[bool, str]`: (is_vulnerable, vulnerability_type) tuple

**Example**:
```python
is_vuln, vuln_type = agent.check_for_vulnerabilities("SQL error in syntax")
if is_vuln:
    print(f"Vulnerability found: {vuln_type}")
```

#### `scan_website() -> bool`

Execute the main scanning loop.

**Returns**:
- `bool`: True if critical vulnerability found, False otherwise

**Raises**:
- General exceptions from command execution

**Example**:
```python
if agent.parse_url("https://example.com"):
    if agent.scan_website():
        print("Critical vulnerability found!")
```

#### `generate_report(output_file: str = None) -> str`

Generate a comprehensive vulnerability report.

**Parameters**:
- `output_file` (str, optional): Output file path. If None, auto-generates path

**Returns**:
- `str`: Path to generated report file

**Example**:
```python
report_path = agent.generate_report()
print(f"Report saved to: {report_path}")

# Or with custom path
custom_report = agent.generate_report("my_report.txt")
```

#### `run(target_url: str) -> Optional[str]`

Main entry point for the bug bounty agent.

**Parameters**:
- `target_url` (str): Target website URL

**Returns**:
- `Optional[str]`: Path to generated report file, or None if failed

**Example**:
```python
agent = BugBountyAgent()
report = agent.run("https://example.com")
if report:
    print(f"Scan completed: {report}")
```

## Utility Classes

### URLValidator

URL validation and normalization utilities.

#### `validate_and_normalize(url: str) -> Tuple[bool, str, str]`

Validate and normalize a URL.

**Returns**:
- `Tuple[bool, str, str]`: (is_valid, normalized_url, domain)

**Example**:
```python
from utils import URLValidator

valid, url, domain = URLValidator.validate_and_normalize("example.com")
```

#### `is_valid_domain(domain: str) -> bool`

Check if string is a valid domain.

**Example**:
```python
if URLValidator.is_valid_domain("example.com"):
    print("Valid domain")
```

### CommandBuilder

Security scanning command generation.

#### `build_curl_headers(url: str, headers: Dict = None) -> str`

Build curl command with optional headers.

**Example**:
```python
from utils import CommandBuilder

cmd = CommandBuilder.build_curl_headers(
    "https://example.com",
    headers={"User-Agent": "Mozilla"}
)
```

#### `build_sql_injection_test(url: str) -> List[str]`

Generate SQL injection test commands.

**Example**:
```python
tests = CommandBuilder.build_sql_injection_test("https://example.com")
```

#### `build_xss_test(url: str) -> List[str]`

Generate XSS test commands.

**Example**:
```python
tests = CommandBuilder.build_xss_test("https://example.com")
```

### VulnerabilityAnalyzer

Vulnerability detection utilities.

#### `analyze(output: str) -> Tuple[bool, List[str]]`

Analyze output for vulnerability indicators.

**Returns**:
- `Tuple[bool, List[str]]`: (is_vulnerable, vulnerability_types)

**Example**:
```python
from utils import VulnerabilityAnalyzer

is_vuln, types = VulnerabilityAnalyzer.analyze(
    "SQL error in your syntax"
)
```

#### `extract_key_info(output: str) -> Dict[str, List[str]]`

Extract key information from command output.

**Returns**:
- `Dict`: Dictionary with keys: headers, errors, server_info, paths

**Example**:
```python
info = VulnerabilityAnalyzer.extract_key_info(curl_output)
print(info['headers'])
```

### ReportGenerator

Report generation utilities.

#### `format_vulnerability(vuln: Dict) -> str`

Format a vulnerability for report output.

**Example**:
```python
from utils import ReportGenerator

formatted = ReportGenerator.format_vulnerability({
    'type': 'sql_injection',
    'severity': 'critical',
    'iteration': 3,
    'command': 'curl ...',
})
```

#### `create_summary(vulns: List[Dict], domain: str, iterations: int) -> str`

Create a summary section for the report.

**Example**:
```python
summary = ReportGenerator.create_summary(
    vulnerabilities,
    "example.com",
    15
)
```

## Configuration

### Environment Variables

```python
import os
from dotenv import load_dotenv

load_dotenv()

openai_key = os.getenv("OPENAI_API_KEY")
max_iter = int(os.getenv("MAX_ITERATIONS", 15))
timeout = int(os.getenv("TIMEOUT", 10))
```

### Configuration Classes

```python
from config import get_config, DevelopmentConfig, ProductionConfig

# Get environment-specific config
config = get_config("production")

# Or use directly
from config import Config

print(Config.OPENAI_MODEL)  # "gpt-4o"
print(Config.MAX_ITERATIONS)  # 15
```

## Data Structures

### Vulnerability Object

```python
vulnerability = {
    "iteration": 3,           # Iteration when found
    "command": "curl ...",    # Command that revealed it
    "indicator": "sql injection",  # Vulnerability type
    "output": "..."           # Evidence output (truncated)
}
```

### Scan History Entry

```python
scan_entry = {
    "phase": "reconnaissance",  # or "command"
    "iteration": 1,
    "command": "curl ...",
    "success": True,
    "output": "...",
    "timestamp": "2024-01-15T10:30:45.123456"
}
```

### Domain Info Object

```python
domain_info = {
    "http_headers": "...",     # HTTP response headers
    "dns_info": "...",         # DNS lookup results
    "whois_info": "...",       # WHOIS data
    "https_status": "443"      # HTTPS port status
}
```

## Error Handling

### Common Exceptions

```python
try:
    agent = BugBountyAgent()
except ValueError as e:
    print(f"Configuration error: {e}")

try:
    success, output = agent.execute_command("invalid command")
except subprocess.TimeoutExpired:
    print("Command timed out")
except Exception as e:
    print(f"Command error: {e}")
```

## Examples

### Basic Scanning

```python
from bug_bounty_agent import BugBountyAgent

agent = BugBountyAgent()
report = agent.run("https://example.com")
print(f"Report: {report}")
```

### Custom Configuration

```python
from bug_bounty_agent import BugBountyAgent

agent = BugBountyAgent()
agent.max_iterations = 20
agent.timeout = 30

report = agent.run("https://example.com")
```

### Manual Workflow

```python
from bug_bounty_agent import BugBountyAgent

agent = BugBountyAgent()

# Step 1: Parse URL
if not agent.parse_url("https://example.com"):
    print("Invalid URL")
    exit(1)

# Step 2: Gather info
info = agent.get_domain_info()
print(f"Domain info: {info}")

# Step 3: Execute commands
success, output = agent.execute_command("curl -I https://example.com")
if success:
    print(f"Command output: {output}")

# Step 4: Analyze
is_vuln, vuln_type = agent.check_for_vulnerabilities(output)
if is_vuln:
    print(f"Vulnerability: {vuln_type}")

# Step 5: Generate report
report = agent.generate_report()
print(f"Report: {report}")
```

### Batch Processing

```python
from bug_bounty_agent import BugBountyAgent

agent = BugBountyAgent()
targets = ["example.com", "example.org", "example.net"]

for target in targets:
    report = agent.run(target)
    if report:
        print(f"✓ {target}: {report}")
    else:
        print(f"✗ {target}: Failed")
```

## Extending the Agent

### Custom Subclass

```python
from bug_bounty_agent import BugBountyAgent

class MyCustomAgent(BugBountyAgent):
    def _generate_fallback_commands(self, iteration):
        return ["custom_cmd_1", "custom_cmd_2"]
    
    def get_domain_info(self):
        info = super().get_domain_info()
        # Add custom info
        info["custom_field"] = "value"
        return info

agent = MyCustomAgent()
report = agent.run("https://example.com")
```

## Rate Limiting

The agent respects API rate limits through:
- Timeout management
- Sequential command execution
- Configurable delays via `REQUEST_DELAY` in config

```python
from config import Config

# Adjust rate limiting
Config.REQUEST_DELAY = 1.0  # 1 second between requests
Config.MAX_RETRIES = 5      # 5 retry attempts
```

---

**Last Updated:** 2024-01-15
**Version:** 1.0
