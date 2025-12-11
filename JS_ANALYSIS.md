# JavaScript Static Analysis Feature

## Overview

The JavaScript Static Analysis module is an advanced feature that automatically extracts and analyzes JavaScript files from web applications to discover:

1. **Leaked Secrets**: API keys, tokens, credentials, and other sensitive data
2. **Hidden API Endpoints**: Undocumented API routes and admin panels
3. **Development Comments**: Sensitive information in code comments

This feature dramatically increases the attack surface discovered during vulnerability scanning by uncovering assets that are not visible in traditional reconnaissance.

## How It Works

### 1. Script Extraction

When the headless browser captures the page DOM, it automatically extracts all `<script src="...">` tags and resolves them to absolute URLs. Only scripts from the target domain are analyzed (CDN scripts are skipped).

### 2. JavaScript File Fetching

The analyzer fetches each JavaScript file and validates:
- Response status (200 OK)
- File size limits (default: 5MB max)
- Content type

### 3. Secret Detection

Uses advanced regex patterns to detect:

| Secret Type | Pattern | Example |
|------------|---------|---------|
| AWS Access Key | `AKIA[0-9A-Z]{16}` | `AKIAIOSFODNN7EXAMPLE` |
| AWS Secret Key | `aws_secret.*=.*[A-Za-z0-9/+=]{40}` | `aws_secret='wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'` |
| Google API Key | `AIza[0-9A-Za-z_-]{35}` | `AIzaSyD...` |
| Google OAuth | `[0-9]+-[0-9A-Za-z_-]{32}\.apps\.googleusercontent\.com` | `123456789-abc...apps.googleusercontent.com` |
| Firebase | `AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}` | Firebase server keys |
| Generic API Key | `api[_-]?key.*=.*[A-Za-z0-9_-]{20,}` | `apiKey: 'abc123...'` |
| Bearer Token | `bearer.*=.*[A-Za-z0-9_-\.]{20,}` | `bearer: 'eyJ...'` |
| JWT Token | `eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+` | `eyJhbGc...` |
| Slack Token | `xox[baprs]-[0-9]{10,13}-...` | `xoxb-123...` |
| GitHub Token | `ghp_[A-Za-z0-9]{36}` | `ghp_abc123...` |
| Private Key | `-----BEGIN (?:RSA |EC )?PRIVATE KEY-----` | PEM private keys |
| Database URL | `mongodb://...` or `mysql://...` | Connection strings |
| Password | `password.*=.*[^"']{8,}` | `password: 'secret123'` |

### 4. Endpoint Discovery

Detects API endpoints using patterns like:

```regex
/api/v[0-9]+/[a-zA-Z0-9_/-]+    # Versioned APIs
/api/[a-zA-Z0-9_/-]+            # General APIs
/admin/[a-zA-Z0-9_/-]+          # Admin panels
/internal/[a-zA-Z0-9_/-]+       # Internal APIs
/graphql                        # GraphQL endpoints
/rest/[a-zA-Z0-9_/-]+          # REST APIs
```

### 5. False Positive Filtering

The analyzer uses intelligent filtering to avoid reporting placeholders:

- Checks for keywords like "example", "placeholder", "your_key", "test", "dummy"
- Validates entropy (real secrets have high randomness)
- Filters out secrets in code comments
- Requires minimum length for values

### 6. Integration with Scanning

Discovered endpoints are automatically fed back into the vulnerability scanning loop:

1. **Planner Agent** receives the list of discovered endpoints
2. **AI strategist** prioritizes testing these hidden endpoints
3. **Executor Agent** tests endpoints for vulnerabilities (SQLi, auth bypass, etc.)
4. **Critic Agent** validates findings

## Usage

The feature is **automatically enabled** when you run a scan:

```bash
python3 cli.py https://example.com
```

### Configuration

No additional configuration is required. The feature uses existing settings:

```bash
# .env file
ENABLE_HEADLESS_BROWSER=true  # Required for JS analysis
TIMEOUT=10                    # Request timeout for fetching JS files
```

### Disabling JS Analysis

If you want to disable only the headless browser (which also disables JS analysis):

```bash
ENABLE_HEADLESS_BROWSER=false python3 cli.py https://example.com
```

## Output

### Console Output

```
[*] Running JavaScript static analysis...
  Found 5 JavaScript file(s) to analyze
  [*] Analyzing: https://example.com/static/js/main.abc123.js
      🔑 Found 2 secret(s)
      🔍 Found 8 endpoint(s)
✓ JS Analysis: Found 2 secret(s) 🔑
✓ JS Analysis: Found 8 hidden endpoint(s) 🔍
  Discovered endpoints will be tested for vulnerabilities
```

### Report Section

The scan report includes a dedicated **JAVASCRIPT STATIC ANALYSIS** section:

```
================================================================================
JAVASCRIPT STATIC ANALYSIS
================================================================================

Analysis Status: completed
JavaScript Files Analyzed: 5
Secrets Discovered: 2
Hidden Endpoints Discovered: 8

LEAKED SECRETS:
  [!] GOOGLE_API_KEY
      Source: https://example.com/static/js/main.js
      Line: 127
      Context: const apiKey = "AIzaSyD..."

  [!] AWS_ACCESS_KEY
      Source: https://example.com/static/js/config.js
      Line: 45
      Context: aws: { accessKeyId: "AKIAIOSFODNN7..."

HIDDEN ENDPOINTS:
  • https://example.com/api/v1/users
  • https://example.com/api/v1/admin/dashboard
  • https://example.com/api/internal/metrics
  • https://example.com/graphql
  ... and 4 more endpoints
```

## Architecture

### New Components

#### 1. `js_static_analyzer.py`

Main module containing the `JSStaticAnalyzer` class:

- `extract_script_urls()` - Extracts <script> tags from HTML
- `fetch_js_file()` - Downloads JavaScript files
- `scan_for_secrets()` - Applies regex patterns to find secrets
- `scan_for_endpoints()` - Discovers API routes
- `analyze_js_file()` - Complete analysis of a single file
- `analyze_all_scripts()` - Batch analysis of all scripts

#### 2. `headless_browser.py` Updates

- `_extract_script_urls()` - New method to extract scripts from Playwright page
- Enhanced `collect_page_data()` to include `script_urls` in results

#### 3. `bug_bounty_agent.py` Integration

- `analyze_javascript_files()` - New method to orchestrate JS analysis
- Integration into `scan_website()` flow
- Storage of discovered endpoints and secrets
- Auto-flagging of critical secrets as vulnerabilities

#### 4. `cognitive_agents.py` Integration

- **PlannerAgent** receives discovered endpoints
- Context preparation includes JS analysis results
- Plan creation prioritizes testing discovered endpoints

## Benefits

### 1. Expanded Attack Surface

Traditional reconnaissance might only find:
- Homepage
- Login page
- Public API docs

With JS analysis, you discover:
- Hidden admin endpoints (`/api/admin/users`)
- Internal APIs (`/internal/metrics`)
- Beta features (`/api/v2/experimental`)
- Developer debug routes

### 2. Immediate Critical Findings

If the analyzer discovers AWS keys or database credentials, the scan immediately:
- Reports them as CRITICAL vulnerabilities
- Sets `critical_found = True`
- Includes detailed context in the report

### 3. Realistic Testing

Modern web apps are JavaScript-heavy (React, Vue, Angular). This feature ensures:
- Single Page Applications (SPAs) are properly analyzed
- Client-side routing is discovered
- Dynamic API calls are captured

### 4. Competitive Advantage

In bug bounty programs, finding secrets in JS files is a common vulnerability:
- **CWE-798**: Use of Hard-coded Credentials
- **CWE-200**: Exposure of Sensitive Information
- **CWE-312**: Cleartext Storage of Sensitive Information

## Performance

- **Concurrent Analysis**: Files can be analyzed in parallel (future enhancement)
- **File Size Limits**: 5MB default limit prevents memory issues
- **Script Limit**: Only analyzes first 10 JS files per page
- **Timeout**: Respects global timeout settings

## Security

- **Domain Scoping**: Only analyzes scripts from target domain
- **Safe Fetching**: Uses proper timeouts and error handling
- **No Execution**: Static analysis only - never executes JavaScript
- **Privacy**: Secrets are logged but can be redacted in reports (future enhancement)

## Examples

### Example 1: AWS Key Discovery

```javascript
// Discovered in: https://example.com/static/js/config.js
const config = {
  aws: {
    accessKeyId: "AKIAIOSFODNN7EXAMPLE",
    secretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
  }
};
```

**Result**: Flagged as CRITICAL vulnerability, scan terminates with findings.

### Example 2: Hidden Admin API

```javascript
// Discovered in: https://example.com/static/js/router.js
const routes = [
  { path: "/", component: Home },
  { path: "/admin/users", component: AdminUsers },  // Hidden!
  { path: "/api/v1/internal/logs", component: Logs }  // Hidden!
];
```

**Result**: Endpoints added to scanning targets, tested for authentication bypass.

### Example 3: Google API Key

```javascript
// Discovered in: https://example.com/static/js/maps.js
const GOOGLE_MAPS_KEY = "AIzaSyD1234567890abcdefghijklmnopqrstuv";
```

**Result**: Flagged as high-risk secret, can be tested for unauthorized usage.

## Limitations

1. **Obfuscated Code**: Heavily minified/obfuscated code may hide secrets
2. **Dynamic Loading**: Scripts loaded after user interaction may be missed
3. **Same-Domain Only**: External scripts (CDNs) are not analyzed
4. **Static Analysis Only**: Cannot detect secrets generated at runtime

## Future Enhancements

- [ ] JavaScript deobfuscation
- [ ] Source map analysis
- [ ] Webpack bundle analysis
- [ ] Environment variable detection
- [ ] Secret validation (test if keys are active)
- [ ] Concurrent file fetching
- [ ] Secret redaction in reports
- [ ] Integration with secret scanning tools (TruffleHog, GitLeaks)

## References

- [OWASP: Hardcoded Passwords](https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password)
- [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- [GitHub: Secret Scanning](https://docs.github.com/en/code-security/secret-scanning)
