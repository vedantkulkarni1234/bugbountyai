"""
JavaScript Static Analysis Module
Extracts and analyzes JavaScript files for secrets and hidden API endpoints.
"""

import re
import requests
from typing import Dict, List, Any, Tuple
from urllib.parse import urljoin, urlparse
from datetime import datetime


class JSStaticAnalyzer:
    """
    Analyzes JavaScript files to discover:
    1. Leaked secrets (API keys, tokens, credentials)
    2. Hidden API endpoints
    3. Development comments with sensitive information
    """
    
    def __init__(self, timeout: int = 10, max_file_size: int = 5 * 1024 * 1024):
        """
        Initialize the JS Static Analyzer.
        
        Args:
            timeout: Request timeout in seconds
            max_file_size: Maximum JS file size to analyze (default 5MB)
        """
        self.timeout = timeout
        self.max_file_size = max_file_size
        self.analyzed_files = []
        self.discovered_secrets = []
        self.discovered_endpoints = []
        
        # Secret patterns
        self.secret_patterns = {
            'aws_access_key': r'AKIA[0-9A-Z]{16}',
            'aws_secret_key': r'aws_secret[_\s]*[=:][_\s]*["\']([A-Za-z0-9/+=]{40})["\']',
            'google_api_key': r'AIza[0-9A-Za-z_-]{35}',
            'google_oauth': r'[0-9]+-[0-9A-Za-z_-]{32}\.apps\.googleusercontent\.com',
            'firebase': r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}',
            'generic_api_key': r'["\']?api[_-]?key["\']?\s*[:=]\s*["\']([A-Za-z0-9_\-]{20,})["\']',
            'bearer_token': r'["\']?bearer["\']?\s*[:=]\s*["\']([A-Za-z0-9_\-\.]{20,})["\']',
            'jwt': r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}',
            'slack_token': r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24,}',
            'github_token': r'ghp_[A-Za-z0-9]{36}',
            'private_key': r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----',
            'database_url': r'(?:mongodb|mysql|postgresql|redis)://[^\s"\']+',
            'password': r'["\']?password["\']?\s*[:=]\s*["\']([^"\']{8,})["\']',
        }
        
        # API endpoint patterns
        self.endpoint_patterns = [
            r'/api/v[0-9]+/[a-zA-Z0-9_/-]+',
            r'/api/[a-zA-Z0-9_/-]+',
            r'/v[0-9]+/[a-zA-Z0-9_/-]+',
            r'/admin/[a-zA-Z0-9_/-]+',
            r'/internal/[a-zA-Z0-9_/-]+',
            r'/graphql',
            r'/rest/[a-zA-Z0-9_/-]+',
            r'/backend/[a-zA-Z0-9_/-]+',
            r'https?://[a-zA-Z0-9.-]+/api/[^\s"\']+',
        ]
    
    def extract_script_urls(self, html_content: str, base_url: str) -> List[str]:
        """
        Extract all JavaScript file URLs from HTML content.
        
        Args:
            html_content: HTML DOM content
            base_url: Base URL for resolving relative paths
            
        Returns:
            List of absolute JavaScript file URLs
        """
        script_urls = []
        
        # Pattern to match <script src="...">
        script_pattern = r'<script[^>]+src=["\']([^"\']+)["\']'
        matches = re.finditer(script_pattern, html_content, re.IGNORECASE)
        
        for match in matches:
            script_url = match.group(1)
            
            # Skip data URLs and external CDN scripts (optional)
            if script_url.startswith('data:'):
                continue
            
            # Convert relative URLs to absolute
            absolute_url = urljoin(base_url, script_url)
            
            # Only analyze scripts from the same domain (avoid CDN analysis)
            base_domain = urlparse(base_url).netloc
            script_domain = urlparse(absolute_url).netloc
            
            if base_domain == script_domain:
                script_urls.append(absolute_url)
        
        return list(set(script_urls))
    
    def fetch_js_file(self, url: str) -> Tuple[bool, str]:
        """
        Fetch JavaScript file content.
        
        Args:
            url: JavaScript file URL
            
        Returns:
            Tuple of (success, content)
        """
        try:
            response = requests.get(
                url,
                timeout=self.timeout,
                headers={'User-Agent': 'Mozilla/5.0 (Security Scanner)'},
                stream=True
            )
            
            # Check content size
            content_length = response.headers.get('content-length')
            if content_length and int(content_length) > self.max_file_size:
                return False, f"File too large: {content_length} bytes"
            
            if response.status_code == 200:
                content = response.text
                
                if len(content) > self.max_file_size:
                    return False, f"Content too large: {len(content)} bytes"
                
                return True, content
            else:
                return False, f"HTTP {response.status_code}"
                
        except Exception as e:
            return False, str(e)
    
    def scan_for_secrets(self, js_content: str, source_url: str) -> List[Dict[str, Any]]:
        """
        Scan JavaScript content for leaked secrets.
        
        Args:
            js_content: JavaScript file content
            source_url: URL of the JS file
            
        Returns:
            List of discovered secrets with metadata
        """
        secrets = []
        
        for secret_type, pattern in self.secret_patterns.items():
            matches = re.finditer(pattern, js_content, re.IGNORECASE)
            
            for match in matches:
                # Get context around the match
                start = max(0, match.start() - 50)
                end = min(len(js_content), match.end() + 50)
                context = js_content[start:end]
                
                # Extract the actual secret value
                secret_value = match.group(0)
                if match.groups():
                    secret_value = match.group(1)
                
                # Validate that it's not a placeholder or example
                if self._is_real_secret(secret_value, context):
                    secret = {
                        'type': secret_type,
                        'value': secret_value,
                        'source': source_url,
                        'context': context.strip(),
                        'line_number': js_content[:match.start()].count('\n') + 1,
                        'discovered_at': datetime.now().isoformat()
                    }
                    secrets.append(secret)
                    self.discovered_secrets.append(secret)
        
        return secrets
    
    def scan_for_endpoints(self, js_content: str, source_url: str) -> List[Dict[str, Any]]:
        """
        Scan JavaScript content for hidden API endpoints.
        
        Args:
            js_content: JavaScript file content
            source_url: URL of the JS file
            
        Returns:
            List of discovered API endpoints with metadata
        """
        endpoints = []
        discovered_urls = set()
        
        for pattern in self.endpoint_patterns:
            matches = re.finditer(pattern, js_content)
            
            for match in matches:
                endpoint = match.group(0)
                
                # Skip if already found
                if endpoint in discovered_urls:
                    continue
                
                # Get context around the match
                start = max(0, match.start() - 50)
                end = min(len(js_content), match.end() + 50)
                context = js_content[start:end]
                
                # Convert relative endpoints to absolute URLs
                if not endpoint.startswith('http'):
                    base_url = self._get_base_url(source_url)
                    absolute_endpoint = urljoin(base_url, endpoint)
                else:
                    absolute_endpoint = endpoint
                
                endpoint_info = {
                    'endpoint': endpoint,
                    'absolute_url': absolute_endpoint,
                    'source': source_url,
                    'context': context.strip(),
                    'line_number': js_content[:match.start()].count('\n') + 1,
                    'discovered_at': datetime.now().isoformat()
                }
                
                endpoints.append(endpoint_info)
                discovered_urls.add(endpoint)
                self.discovered_endpoints.append(endpoint_info)
        
        return endpoints
    
    def analyze_js_file(self, url: str, base_url: str) -> Dict[str, Any]:
        """
        Complete analysis of a single JavaScript file.
        
        Args:
            url: JavaScript file URL
            base_url: Base URL of the target website
            
        Returns:
            Analysis results including secrets and endpoints
        """
        print(f"  [*] Analyzing: {url}")
        
        success, content = self.fetch_js_file(url)
        
        if not success:
            return {
                'url': url,
                'status': 'failed',
                'reason': content,
                'secrets': [],
                'endpoints': []
            }
        
        # Scan for secrets and endpoints
        secrets = self.scan_for_secrets(content, url)
        endpoints = self.scan_for_endpoints(content, base_url)
        
        result = {
            'url': url,
            'status': 'analyzed',
            'file_size': len(content),
            'secrets': secrets,
            'endpoints': endpoints,
            'analyzed_at': datetime.now().isoformat()
        }
        
        self.analyzed_files.append(result)
        
        # Print summary
        if secrets:
            print(f"      🔑 Found {len(secrets)} secret(s)")
        if endpoints:
            print(f"      🔍 Found {len(endpoints)} endpoint(s)")
        
        return result
    
    def analyze_all_scripts(
        self, 
        html_content: str, 
        base_url: str
    ) -> Dict[str, Any]:
        """
        Extract and analyze all JavaScript files from HTML.
        
        Args:
            html_content: HTML DOM content
            base_url: Base URL of the target website
            
        Returns:
            Complete analysis results
        """
        print("\n[JS Static Analyzer] Extracting JavaScript files...")
        
        script_urls = self.extract_script_urls(html_content, base_url)
        
        print(f"  Found {len(script_urls)} JavaScript file(s) to analyze")
        
        if not script_urls:
            return {
                'status': 'no_scripts_found',
                'script_urls': [],
                'analyses': [],
                'total_secrets': 0,
                'total_endpoints': 0
            }
        
        analyses = []
        for script_url in script_urls[:10]:  # Limit to 10 files for performance
            analysis = self.analyze_js_file(script_url, base_url)
            analyses.append(analysis)
        
        total_secrets = sum(len(a.get('secrets', [])) for a in analyses)
        total_endpoints = sum(len(a.get('endpoints', [])) for a in analyses)
        
        return {
            'status': 'completed',
            'script_urls': script_urls,
            'analyses': analyses,
            'total_secrets': total_secrets,
            'total_endpoints': total_endpoints,
            'analyzed_at': datetime.now().isoformat()
        }
    
    def _is_real_secret(self, value: str, context: str) -> bool:
        """
        Validate if a matched secret is real or just a placeholder.
        
        Args:
            value: The matched secret value
            context: Surrounding code context
            
        Returns:
            True if likely a real secret, False if placeholder
        """
        # Common placeholder/example patterns
        placeholder_patterns = [
            r'example',
            r'placeholder',
            r'your[_-]?key',
            r'insert[_-]?here',
            r'xxx+',
            r'000+',
            r'test',
            r'dummy',
            r'fake',
            r'sample',
        ]
        
        value_lower = value.lower()
        context_lower = context.lower()
        
        # Check if value or context contains placeholder indicators
        for pattern in placeholder_patterns:
            if re.search(pattern, value_lower) or re.search(pattern, context_lower):
                return False
        
        # Check for entropy (real secrets typically have high entropy)
        if len(value) < 10:
            return False
        
        # If the value looks like "key: 'AKIA...'" it's more likely real
        # If it's in a comment, it might be documentation
        if '//' in context or '/*' in context or '*/' in context:
            return False
        
        return True
    
    def _get_base_url(self, url: str) -> str:
        """
        Get base URL from a full URL.
        
        Args:
            url: Full URL
            
        Returns:
            Base URL (scheme + netloc)
        """
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}"
    
    def get_discovered_endpoints_for_scanning(self) -> List[str]:
        """
        Get list of discovered endpoints suitable for vulnerability scanning.
        
        Returns:
            List of absolute endpoint URLs
        """
        return [ep['absolute_url'] for ep in self.discovered_endpoints]
    
    def get_summary(self) -> Dict[str, Any]:
        """
        Get summary of all JS analysis results.
        
        Returns:
            Summary dictionary
        """
        return {
            'total_files_analyzed': len(self.analyzed_files),
            'total_secrets_found': len(self.discovered_secrets),
            'total_endpoints_found': len(self.discovered_endpoints),
            'secret_types': list(set(s['type'] for s in self.discovered_secrets)),
            'high_risk_secrets': [
                s for s in self.discovered_secrets 
                if s['type'] in ['aws_access_key', 'aws_secret_key', 'private_key', 'database_url']
            ]
        }
