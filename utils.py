"""
Utility functions for the Bug Bounty Agent.
"""

import re
import json
from datetime import datetime
from typing import Dict, List, Tuple, Optional
from urllib.parse import urlparse, urljoin


class URLValidator:
    """Utilities for URL validation and normalization."""
    
    @staticmethod
    def validate_and_normalize(url: str) -> Tuple[bool, str, str]:
        """
        Validate and normalize a URL.
        
        Returns:
            Tuple of (is_valid, normalized_url, domain)
        """
        try:
            if not url.startswith(('http://', 'https://')):
                url = f'https://{url}'
            
            parsed = urlparse(url)
            
            if not parsed.netloc:
                return False, "", ""
            
            return True, url, parsed.netloc
        except Exception as e:
            return False, "", ""
    
    @staticmethod
    def is_valid_domain(domain: str) -> bool:
        """Check if string is a valid domain."""
        pattern = r'^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$'
        return bool(re.match(pattern, domain.lower()))
    
    @staticmethod
    def extract_domain(url: str) -> str:
        """Extract domain from URL."""
        parsed = urlparse(url)
        return parsed.netloc or url


class CommandBuilder:
    """Utilities for building security scanning commands."""
    
    @staticmethod
    def build_curl_headers(url: str, headers: Dict = None) -> str:
        """Build curl command with headers."""
        cmd = f'curl -s -I -L "{url}"'
        if headers:
            for key, value in headers.items():
                cmd += f' -H "{key}: {value}"'
        return cmd
    
    @staticmethod
    def build_sql_injection_test(url: str) -> List[str]:
        """Generate SQL injection test commands."""
        tests = [
            f"curl -s \"{url}' OR '1'='1\"",
            f"curl -s \"{url}' UNION SELECT NULL--\"",
            f"curl -s \"{url}' AND 1=1--\"",
        ]
        return tests
    
    @staticmethod
    def build_xss_test(url: str) -> List[str]:
        """Generate XSS test commands."""
        tests = [
            f"curl -s \"{url}<script>alert(1)</script>\"",
            f"curl -s \"{url}\\\"onmouseover=alert(1)\\\"\"",
        ]
        return tests
    
    @staticmethod
    def build_directory_traversal_tests(url: str) -> List[str]:
        """Generate directory traversal test commands."""
        tests = [
            f"curl -s \"{url}/../../../etc/passwd\"",
            f"curl -s \"{url}/../../config.php\"",
        ]
        return tests


class VulnerabilityAnalyzer:
    """Utilities for analyzing potential vulnerabilities."""
    
    # Vulnerability patterns
    PATTERNS = {
        'sql_injection': [
            r'sql\s+error',
            r'syntax\s+error',
            r'warning:\s+mysql',
            r'fatal\s+error.*mysql',
            r'you have an error',
            r'unclosed quotation mark',
        ],
        'rce': [
            r'remote\s+code\s+execution',
            r'rce',
            r'command\s+injection',
            r'os\s+command',
            r'shell\s+access',
        ],
        'xss': [
            r'<script>',
            r'javascript:',
            r'onerror=',
            r'onload=',
            r'cross.?site',
        ],
        'authentication_bypass': [
            r'authentication\s+bypass',
            r'unauthorized\s+access',
            r'login\s+bypass',
            r'password\s+reset\s+flaw',
        ],
        'ssrf': [
            r'server.?side\s+request\s+forgery',
            r'ssrf',
            r'internal\s+request',
        ],
        'xxe': [
            r'xml\s+external\s+entity',
            r'xxe',
            r'external\s+entity',
        ],
        'path_traversal': [
            r'path\s+traversal',
            r'directory\s+traversal',
            r'\.\.\/.*\.\.\/',
        ]
    }
    
    @staticmethod
    def analyze(output: str) -> Tuple[bool, List[str]]:
        """
        Analyze output for vulnerability indicators.
        
        Returns:
            Tuple of (is_vulnerable, vulnerability_types)
        """
        found_vulns = []
        output_lower = output.lower()
        
        for vuln_type, patterns in VulnerabilityAnalyzer.PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, output_lower):
                    found_vulns.append(vuln_type)
                    break
        
        return len(found_vulns) > 0, found_vulns
    
    @staticmethod
    def extract_key_info(output: str) -> Dict[str, List[str]]:
        """Extract key information from command output."""
        info = {
            'headers': [],
            'errors': [],
            'server_info': [],
            'paths': [],
        }
        
        # Extract headers
        header_pattern = r'^([A-Za-z-]+):\s*(.+)$'
        for line in output.split('\n'):
            if re.match(header_pattern, line):
                info['headers'].append(line.strip())
        
        # Extract errors
        error_keywords = ['error', 'warning', 'fatal', 'exception']
        for keyword in error_keywords:
            pattern = f'.*{keyword}.*'
            matches = re.findall(pattern, output, re.IGNORECASE)
            info['errors'].extend(matches[:3])
        
        # Extract server info
        server_pattern = r'Server:\s*([^\n]+)'
        server_matches = re.findall(server_pattern, output, re.IGNORECASE)
        info['server_info'].extend(server_matches)
        
        return info


class ReportGenerator:
    """Utilities for generating reports."""
    
    @staticmethod
    def format_vulnerability(vuln: Dict) -> str:
        """Format a vulnerability for report output."""
        lines = []
        lines.append("[VULNERABILITY]")
        lines.append(f"Type: {vuln.get('type', 'Unknown')}")
        lines.append(f"Severity: {vuln.get('severity', 'Unknown').upper()}")
        lines.append(f"Iteration: {vuln.get('iteration', 'N/A')}")
        lines.append(f"Command: {vuln.get('command', 'N/A')}")
        lines.append(f"Description: {vuln.get('description', 'N/A')}")
        lines.append(f"Evidence:\n{vuln.get('evidence', 'N/A')}")
        lines.append("")
        return "\n".join(lines)
    
    @staticmethod
    def create_summary(vulns: List[Dict], domain: str, iterations: int) -> str:
        """Create a summary section for the report."""
        lines = []
        lines.append("=" * 80)
        lines.append("SUMMARY")
        lines.append("=" * 80)
        lines.append(f"Target: {domain}")
        lines.append(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"Total Iterations: {iterations}")
        lines.append(f"Vulnerabilities Found: {len(vulns)}")
        
        if vulns:
            severity_counts = {}
            for vuln in vulns:
                sev = vuln.get('severity', 'unknown').upper()
                severity_counts[sev] = severity_counts.get(sev, 0) + 1
            
            lines.append("\nVulnerability Breakdown:")
            for severity, count in severity_counts.items():
                lines.append(f"  - {severity}: {count}")
        
        lines.append("")
        return "\n".join(lines)


class Logger:
    """Simple logging utility."""
    
    @staticmethod
    def info(message: str):
        """Log info message."""
        print(f"[INFO] {message}")
    
    @staticmethod
    def success(message: str):
        """Log success message."""
        print(f"✓ {message}")
    
    @staticmethod
    def error(message: str):
        """Log error message."""
        print(f"❌ {message}")
    
    @staticmethod
    def warning(message: str):
        """Log warning message."""
        print(f"⚠ {message}")
    
    @staticmethod
    def debug(message: str, debug: bool = False):
        """Log debug message."""
        if debug:
            print(f"[DEBUG] {message}")


class JsonFormatter:
    """Utilities for JSON formatting."""
    
    @staticmethod
    def safe_dumps(obj, indent=2) -> str:
        """Safely convert object to JSON string."""
        try:
            return json.dumps(obj, indent=indent, default=str)
        except Exception:
            return str(obj)
    
    @staticmethod
    def safe_loads(json_str: str) -> Dict:
        """Safely load JSON string."""
        try:
            return json.loads(json_str)
        except Exception:
            return {}
