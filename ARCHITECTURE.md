# Architecture Documentation

## System Overview

The Autonomous AI Bug Bounty Agent is a sophisticated vulnerability scanning system that combines command execution with AI-driven analysis.

```
┌─────────────────────────────────────────────────────────────────┐
│                    User Interface (CLI)                         │
│                        (cli.py)                                 │
└────────────────────────┬────────────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────────────┐
│              Bug Bounty Agent Core                              │
│                  (bug_bounty_agent.py)                          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
│  │ Reconnaissance│  │ AI Analysis  │  │ Scanning     │          │
│  │   Module     │  │   Module     │  │   Module     │          │
│  └──────────────┘  └──────────────┘  └──────────────┘          │
└────────────────────────┬────────────────────────────────────────┘
                         │
        ┌────────────────┼────────────────┐
        │                │                │
        ▼                ▼                ▼
        ┌─────────┐    ┌──────────────┐  ┌─────────────┐
        │ Google  │    │  Shell Cmds  │  │   Utilities │
        │ Gemini  │    │  (curl, etc) │  │ (utils.py)  │
        └─────────┘    └──────────────┘  └─────────────┘
```

## Module Architecture

### 1. **bug_bounty_agent.py** - Core Agent Module
Main module containing the `BugBountyAgent` class.

**Key Classes:**
- `BugBountyAgent`: Main scanning orchestrator

**Key Methods:**
- `parse_url()`: URL validation and parsing
- `get_domain_info()`: Initial reconnaissance
- `analyze_with_ai()`: AI analysis of findings
- `execute_command()`: Execute shell commands safely
- `check_for_vulnerabilities()`: Pattern matching for vulnerabilities
- `scan_website()`: Main scanning loop
- `generate_report()`: Report generation
- `run()`: Main entry point

**Responsibilities:**
- URL parsing and validation
- Command execution management
- AI integration with Google Gemini API
- Vulnerability pattern detection
- Scan orchestration and iteration
- Report generation

### 2. **cli.py** - Command-Line Interface
User-facing CLI wrapper.

**Key Functions:**
- `parse_arguments()`: Argument parsing
- `main()`: CLI entry point

**Responsibilities:**
- Argument parsing and validation
- User input handling
- CLI output formatting
- Report display

### 3. **config.py** - Configuration Management
Centralized configuration.

**Key Classes:**
- `Config`: Base configuration
- `DevelopmentConfig`: Development settings
- `ProductionConfig`: Production settings
- `TestingConfig`: Testing settings

**Responsibilities:**
- Environment-based configuration
- API key management
- Scanning parameters
- Vulnerability indicators
- Port definitions

### 4. **utils.py** - Utility Functions
Helper utilities for various operations.

**Key Classes:**
- `URLValidator`: URL validation and normalization
- `CommandBuilder`: Command generation
- `VulnerabilityAnalyzer`: Vulnerability detection
- `ReportGenerator`: Report formatting
- `Logger`: Logging utilities
- `JsonFormatter`: JSON handling

**Responsibilities:**
- URL processing
- Command construction
- Pattern-based vulnerability detection
- Report generation
- Logging
- JSON serialization

### 5. **headless_browser.py** - Playwright Controller
Dedicated utilities for rendering targets inside a headless Chromium browser.

**Key Classes:**
- `HeadlessBrowser`: Manages Playwright sessions, screenshots, and DOM extraction

**Responsibilities:**
- Launch Chromium with safe defaults (no-sandbox, headless)
- Capture rendered HTML, console logs, and form metadata
- Simulate basic user actions (scrolling, button clicks, text input)
- Generate screenshots stored under `reports/browser/screenshots`

### 6. **test_agent.py** - Test Suite
Unit and integration tests.

**Test Classes:**
- `TestURLValidator`: URL validation tests
- `TestCommandBuilder`: Command building tests
- `TestVulnerabilityAnalyzer`: Vulnerability detection tests
- `TestBugBountyAgent`: Agent functionality tests
- `TestIntegration`: Integration tests

## Data Flow

### Scanning Workflow

```
1. User Input
   ↓
2. URL Validation & Parsing
   ↓
3. Initial Reconnaissance
    ├─ HTTP Headers
    ├─ DNS Lookup
    ├─ WHOIS Query
    ├─ Port Testing
    └─ (Optional) Headless browser DOM/screenshot capture
    ↓
4. Iteration Loop (up to MAX_ITERATIONS)

    ├─ Receive vulnerability scanning suggestions
    ├─ Execute suggested commands
    ├─ Analyze output for vulnerabilities
    ├─ Check for critical vulnerability
    └─ Update history and context
   ↓
5. Report Generation
   ├─ Compile findings
   ├─ Generate recommendations
   └─ Save to file
   ↓
6. Output
```

### AI Analysis Loop

```
Context (previous findings)
        ↓
    OpenAI API
   (GPT-4 model)
        ↓
AI Response (suggested commands)
        ↓
Command Extraction
        ↓
Command Execution
        ↓
Output Analysis
        ↓
Vulnerability Detection
        ↓
Update Context
        ↓
[Loop/Exit Decision]
```

## Key Algorithms

### 1. Vulnerability Detection Algorithm
```python
for pattern in CRITICAL_INDICATORS:
    if re.search(pattern, output):
        return VULNERABLE
```

Patterns checked:
- SQL injection indicators
- RCE indicators
- XSS indicators
- Authentication bypass indicators
- Other critical vulnerabilities

### 2. Command Extraction Algorithm
```python
for line in ai_response.split('\n'):
    if line.startswith(COMMAND_PREFIXES):
        extract_and_validate(line)
```

Command prefixes:
- curl
- nmap
- ffuf
- sqlmap
- nikto
- wget

### 3. Iteration Strategy
```
Iteration 1-2: Basic reconnaissance
Iteration 3-6: Initial vulnerability testing
Iteration 7-12: Deep vulnerability scanning
Iteration 13+: Exploitation attempts
```

## Configuration System

### Environment Variables
```
OPENAI_API_KEY      - Required: OpenAI API key
MAX_ITERATIONS      - Optional: Max scan iterations (default: 15)
TIMEOUT             - Optional: Command timeout in seconds (default: 10)
```

### Configuration Hierarchy
1. Environment variables (highest priority)
2. `.env` file
3. Default values in `config.py` (lowest priority)

## Error Handling

### Command Execution
- Timeout handling (subprocess.TimeoutExpired)
- Exception catching for all shell operations
- Graceful fallback to next command

### API Calls
- OpenAI API error handling
- Fallback to alternative scanning strategies
- Rate limiting awareness

### URL Validation
- Protocol validation
- Domain validation
- Netloc extraction

## Security Considerations

### Input Validation
- URL validation before processing
- Command output sanitization
- API response validation

### Command Execution
- No shell metacharacter injection
- Subprocess safety (limited to predefined commands)
- Timeout protection

### API Security
- API key from environment (not hardcoded)
- Secure API key handling
- Rate limiting support

## Performance Characteristics

### Time Complexity
- URL parsing: O(1)
- Initial reconnaissance: O(n) where n = number of reconnaissance types
- Per-iteration: O(m) where m = number of commands
- Report generation: O(p) where p = number of findings

### Space Complexity
- Scan history: O(i) where i = iterations
- Vulnerability list: O(v) where v = vulnerabilities found
- Report string: O(s) where s = report size

### Typical Execution Times
- Reconnaissance: 10-30 seconds
- Per iteration: 5-20 seconds
- Total scan: 2-5 minutes
- Report generation: <1 second

## Extensibility Points

### 1. Custom Scanning Strategies
```python
class CustomAgent(BugBountyAgent):
    def _generate_fallback_commands(self, iteration):
        return ["custom_command_1", "custom_command_2"]
```

### 2. Custom Vulnerability Detectors
```python
class CustomAnalyzer(VulnerabilityAnalyzer):
    PATTERNS = {
        'custom_vuln': [r'custom_pattern_1', r'custom_pattern_2']
    }
```

### 3. Report Format Customization
```python
def generate_report(self, output_file=None, format='txt'):
    # Custom format support
    pass
```

### 4. AI Model Customization
```python
OPENAI_MODEL = "gpt-4o"  # Can be changed in config.py
```

## Dependencies

### External Libraries
- `requests`: HTTP requests (optional)
- `openai`: OpenAI API client
- `python-dotenv`: Environment variable management
- `dnspython`: DNS utilities (optional)
- `playwright`: Headless browser automation and DOM capture

### System Requirements
- Python 3.8+
- Linux/Unix shell environment
- curl, nmap, and other security tools (optional)

## Testing Strategy

### Unit Tests
- URL validation
- Command building
- Vulnerability detection
- Agent initialization

### Integration Tests
- Full scanning workflow
- AI interaction
- Report generation

### Mock Objects
- OpenAI API responses
- Command execution output
- File operations

## Future Enhancements

1. **Multi-threaded Scanning**
   - Parallel command execution
   - Concurrent AI requests

2. **Machine Learning**
   - Pattern learning from results
   - Adaptive scanning strategies

3. **Database Integration**
   - Store findings
   - Track vulnerability trends
   - Compare scans over time

4. **Report Formats**
   - HTML reports
   - JSON exports
   - PDF generation

5. **Additional Integration**
   - Slack notifications
   - Jira integration
   - Webhook support

6. **Advanced Analysis**
   - Severity scoring
   - CVSS rating
   - Exploit database matching

## Monitoring and Logging

### Log Levels
- INFO: General operation information
- DEBUG: Detailed debugging information
- WARNING: Non-critical issues
- ERROR: Critical errors

### Metrics
- Commands executed
- Vulnerabilities found
- AI response time
- Total scan duration

---

**Last Updated:** 2024-01-15
**Version:** 1.0
