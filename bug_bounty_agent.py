#!/usr/bin/env python3
"""
Expert Level Autonomous AI Bug Bounty Agent
This module contains the core logic for the autonomous vulnerability scanner.
"""

import os
import json
import subprocess
import re
from datetime import datetime
from typing import Any, Dict, List, Tuple, Optional
from urllib.parse import urlparse

import requests
from dotenv import load_dotenv

try:
    import google.generativeai as genai
except ImportError:
    genai = None

from headless_browser import HeadlessBrowser
from cognitive_agents import PlannerAgent, ExecutorAgent, CriticAgent
from js_static_analyzer import JSStaticAnalyzer


class BugBountyAgent:
    """
    An autonomous AI-powered bug bounty scanning agent with cognitive architecture.
    
    Uses a Planner-Executor-Critic architecture:
    1. Planner: Creates strategic scanning plans based on reconnaissance
    2. Executor: Runs scanning commands and collects output
    3. Critic: Validates findings to reduce false positives
    
    Features:
    - Headless browser with Playwright for JavaScript and DOM analysis
    - AI-driven vulnerability discovery with Google Gemini
    - Context-aware pattern matching
    - Comprehensive reporting
    """

    def __init__(self):
        load_dotenv()
        
        self.api_key = os.getenv("GOOGLE_API_KEY")
        if not self.api_key:
            raise ValueError("GOOGLE_API_KEY environment variable not set")
        
        if genai is None:
            raise ImportError("google-generativeai package not installed")
        
        genai.configure(api_key=self.api_key)
        self.model = genai.GenerativeModel("gemini-2.5-flash")
        self.max_iterations = int(os.getenv("MAX_ITERATIONS", 15))
        self.timeout = int(os.getenv("TIMEOUT", 10))
        self.enable_headless_browser = os.getenv("ENABLE_HEADLESS_BROWSER", "true").lower() not in {"0", "false", "no", "off"}
        self.enable_cognitive_mode = os.getenv("ENABLE_COGNITIVE_MODE", "true").lower() not in {"0", "false", "no", "off"}
        
        # Core components
        self.headless_browser = HeadlessBrowser()
        self.browser_intel: Dict[str, Any] = {}
        self.js_analyzer = JSStaticAnalyzer(timeout=self.timeout)
        
        # Cognitive agents
        self.planner = PlannerAgent(self.model)
        self.executor = ExecutorAgent(self.execute_command)
        self.critic = CriticAgent(self.model)
        
        # State
        self.target_url = None
        self.domain = None
        self.vulnerabilities = []
        self.scan_history = []
        self.critical_found = False
        self.js_analysis_results: Dict[str, Any] = {}
        self.discovered_endpoints = []
        
    def parse_url(self, url: str) -> bool:
        """Parse and validate the target URL."""
        try:
            parsed = urlparse(url)
            if not parsed.scheme:
                url = f"https://{url}"
                parsed = urlparse(url)
            
            if not parsed.netloc:
                print(f"❌ Invalid URL format: {url}")
                return False
            
            self.target_url = url
            self.domain = parsed.netloc
            print(f"✓ Target URL: {self.target_url}")
            print(f"✓ Domain: {self.domain}")
            return True
        except Exception as e:
            print(f"❌ Error parsing URL: {e}")
            return False

    def execute_command(self, command: str) -> Tuple[bool, str]:
        """Execute a shell command and return the result."""
        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            return True, result.stdout + result.stderr
        except subprocess.TimeoutExpired:
            return False, f"Command timed out after {self.timeout}s"
        except Exception as e:
            return False, str(e)

    def get_domain_info(self) -> Dict[str, str]:
        """Gather initial domain reconnaissance information."""
        print("\n[*] Gathering domain information...")
        info = {}
        
        # Get HTTP headers and basic info
        success, output = self.execute_command(f"curl -I -L -s {self.target_url} | head -20")
        if success:
            info["http_headers"] = output
        
        # DNS lookup
        success, output = self.execute_command(f"nslookup {self.domain} 2>/dev/null || dig {self.domain}")
        if success:
            info["dns_info"] = output[:500]
        
        # Whois info (basic)
        success, output = self.execute_command(f"whois {self.domain} 2>/dev/null | head -30")
        if success:
            info["whois_info"] = output
        
        # Check for common ports
        success, output = self.execute_command(
            f"timeout 2 curl -s -o /dev/null -w '%{{http_code}}' https://{self.domain}:443"
        )
        if success:
            info["https_status"] = output
        
        return info

    def gather_browser_intel(self) -> Dict[str, Any]:
        """Use Playwright to render the page and capture dynamic context."""
        if not self.target_url:
            return {}
        
        if not self.enable_headless_browser:
            data = {"status": "skipped", "reason": "headless_browser_disabled"}
            self.browser_intel = data
            self._record_browser_history(data)
            return data
        
        if not self.headless_browser.is_available():
            print("⚠ Playwright is not installed. Skipping headless browser capture.")
            data = {"status": "skipped", "reason": "playwright_not_available"}
            self.browser_intel = data
            self._record_browser_history(data)
            return data
        
        print("\n[*] Capturing headless browser intelligence (Playwright)...")
        browser_data = self.headless_browser.collect_page_data(self.target_url)
        self.browser_intel = browser_data
        self._record_browser_history(browser_data)
        status = browser_data.get("status")
        reason = browser_data.get("reason")
        if status == "captured":
            print("✓ Headless browser capture complete.")
        elif reason:
            print(f"⚠ Headless browser capture result: {reason}")
        else:
            print(f"⚠ Headless browser capture status: {status}")
        return browser_data

    def analyze_javascript_files(self, browser_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze JavaScript files for secrets and hidden endpoints."""
        if not browser_data or browser_data.get("status") != "captured":
            return {"status": "skipped", "reason": "no_browser_data"}
        
        rendered_dom = browser_data.get("rendered_dom", "")
        if not rendered_dom:
            return {"status": "skipped", "reason": "no_dom_content"}
        
        print("\n[*] Running JavaScript static analysis...")
        js_results = self.js_analyzer.analyze_all_scripts(rendered_dom, self.target_url)
        self.js_analysis_results = js_results
        
        # Store discovered endpoints for future scanning
        if js_results.get("status") == "completed":
            self.discovered_endpoints = self.js_analyzer.get_discovered_endpoints_for_scanning()
            
            # Report findings
            total_secrets = js_results.get("total_secrets", 0)
            total_endpoints = js_results.get("total_endpoints", 0)
            
            if total_secrets > 0:
                print(f"✓ JS Analysis: Found {total_secrets} secret(s) 🔑")
                
                # Add high-risk secrets as vulnerabilities
                for analysis in js_results.get("analyses", []):
                    for secret in analysis.get("secrets", []):
                        if secret["type"] in ["aws_access_key", "aws_secret_key", "private_key", "database_url", "google_api_key"]:
                            self.vulnerabilities.append({
                                "type": "leaked_secret",
                                "secret_type": secret["type"],
                                "source": secret["source"],
                                "confidence": 0.95,
                                "reasoning": f"High-risk secret discovered in JavaScript: {secret['type']}",
                                "context": secret["context"][:200],
                                "severity": "CRITICAL"
                            })
                            self.critical_found = True
            
            if total_endpoints > 0:
                print(f"✓ JS Analysis: Found {total_endpoints} hidden endpoint(s) 🔍")
                print(f"  Discovered endpoints will be tested for vulnerabilities")
        
        # Record in scan history
        self.scan_history.append({
            "phase": "javascript_analysis",
            "timestamp": datetime.now().isoformat(),
            "status": js_results.get("status"),
            "secrets_found": js_results.get("total_secrets", 0),
            "endpoints_found": js_results.get("total_endpoints", 0)
        })
        
        return js_results

    def analyze_with_ai(self, context: str, instruction: str) -> str:
        """Use Google Gemini to analyze information and determine next steps."""
        try:
            system_prompt = """You are an expert ethical hacker and bug bounty hunter. 
Your role is to identify vulnerabilities in web applications through systematic testing.
Respond with actionable commands and insights based on reconnaissance data.
Focus on finding critical vulnerabilities like SQLi, RCE, SSRF, XSS, authentication bypass, etc.
Always suggest commands that can be executed in a Linux terminal.
Be thorough but efficient - prioritize critical vulnerability discovery."""
            
            user_message = f"{system_prompt}\n\n{instruction}\n\nContext:\n{context}"
            
            response = self.model.generate_content(
                user_message,
                generation_config=genai.types.GenerationConfig(
                    temperature=0.7,
                    max_output_tokens=1000
                )
            )
            return response.text
        except Exception as e:
            print(f"⚠ AI analysis error: {e}")
            return ""

    def extract_commands_from_response(self, response: str) -> List[str]:
        """Extract executable commands from AI response.
        Only extracts safe, legitimate scanning commands.
        """
        commands = []
        
        # Whitelist of allowed command prefixes
        allowed_commands = ['curl', 'nmap', 'ffuf', 'sqlmap', 'nikto', 'wget', 'python']
        
        lines = response.split('\n')
        for line in lines:
            line = line.strip()
            
            # Only extract lines that start with allowed commands
            if any(line.startswith(f"{cmd} ") for cmd in allowed_commands):
                # Reject commands with dangerous patterns
                if not any(suspect in line.lower() for suspect in ['rm -', 'dd if=', 'mkfs', 'rm\\ -']):
                    commands.append(line)
        
        return commands

    def check_for_vulnerabilities(self, output: str) -> Tuple[bool, str]:
        """Check if output indicates a critical vulnerability.
        Uses context-aware pattern matching to reduce false positives.
        """
        # Patterns that indicate actual vulnerabilities (not just mentions)
        # These look for actual error messages and evidence, not just keywords
        vulnerable_indicators = [
            # SQL Injection specific evidence
            r"error in.*sql|sql.*error|you have an error.*sql|mysql_fetch|unclosed quotation mark",
            r"syntax error.*near.*or|near\s+.*'.*'.*'",
            # RCE/Command Injection evidence
            r"(?:remote\s+code\s+execution|command\s+injection).*(?:vulnerability|exploit)",
            r"shell\s+access|shell\s+execution|command\s+output",
            # XXE evidence
            r"(?:xml\s+external\s+entity|xxe).*(?:vulnerability|exploit|payload)",
            # Authentication bypass (explicit)
            r"(?:authentication|login)\s+(?:bypass|failed).*(?:success|exploit)",
            # Path Traversal with evidence
            r"(?:etc/passwd|windows/system|config\.php|\.\.\/)",
            # SSRF evidence
            r"(?:server.?side|ssrf).*(?:request|exploit|vulnerability)",
        ]
        
        # Patterns that are too generic and often false positives
        # These need additional context
        mention_indicators = [
            (r'\bxss\b', r'<script>|javascript:|onerror=|onload='),  # Only count if also has payload evidence
            (r'\bcsrf\b', r'csrf\s+token|cross.?site|request\s+forgery'),
            (r'\b(?:vulnerability|vulnerabilities)\b', r'(?:critical|high|severe|exploit)'),  # Only if severity mentioned
        ]
        
        output_lower = output.lower()
        
        # Check strong indicators
        for pattern in vulnerable_indicators:
            if re.search(pattern, output_lower):
                return True, pattern
        
        # Check mention indicators - require supporting evidence
        for keyword_pattern, evidence_pattern in mention_indicators:
            if re.search(keyword_pattern, output_lower) and re.search(evidence_pattern, output_lower):
                return True, keyword_pattern
        
        return False, ""

    def scan_website(self) -> bool:
        """
        Execute the main scanning loop using cognitive architecture.
        Uses Planner-Executor-Critic pattern for intelligent scanning.
        """
        print(f"\n{'='*60}")
        print(f"Starting autonomous scan of {self.domain}")
        if self.enable_cognitive_mode:
            print("Mode: Cognitive Architecture (Planner-Executor-Critic)")
        else:
            print("Mode: Legacy Linear Scanning")
        print(f"{'='*60}\n")
        
        # Phase 1: Initial reconnaissance
        domain_info = self.get_domain_info()
        browser_data = self.gather_browser_intel()
        if browser_data:
            domain_info["headless_browser"] = self._summarize_browser_data(browser_data)
        self.scan_history.append({
            "phase": "reconnaissance",
            "timestamp": datetime.now().isoformat(),
            "data": domain_info
        })
        
        # Phase 2: JavaScript static analysis
        js_results = self.analyze_javascript_files(browser_data)
        if js_results.get("status") == "completed":
            domain_info["js_analysis"] = {
                "secrets_found": js_results.get("total_secrets", 0),
                "endpoints_found": js_results.get("total_endpoints", 0),
                "discovered_endpoints": self.discovered_endpoints[:5]
            }
        
        # Check if critical secrets were found
        if self.critical_found:
            print("\n🚨 CRITICAL: High-risk secrets discovered in JavaScript files!")
            return True
        
        # Choose scanning mode
        if self.enable_cognitive_mode:
            return self._scan_with_cognitive_architecture(domain_info, browser_data)
        else:
            return self._scan_legacy_mode(domain_info)
    
    def _scan_with_cognitive_architecture(
        self, 
        domain_info: Dict[str, Any], 
        browser_data: Dict[str, Any]
    ) -> bool:
        """
        Cognitive architecture scanning with Planner-Executor-Critic.
        """
        iteration = 0
        
        while iteration < self.max_iterations and not self.critical_found:
            iteration += 1
            print(f"\n{'='*60}")
            print(f"[Iteration {iteration}/{self.max_iterations}]")
            print(f"{'='*60}")
            
            # Step 1: PLANNER - Create strategic scanning plan
            plan = self.planner.create_scanning_plan(
                domain=self.domain,
                domain_info=domain_info,
                browser_data=browser_data,
                iteration=iteration,
                discovered_endpoints=self.discovered_endpoints
            )
            
            # Step 2: EXECUTOR - Execute the plan
            execution_results = self.executor.execute_plan(plan)
            
            # Step 3: CRITIC - Validate findings
            for result in execution_results:
                if not result["success"] or not result["output"]:
                    continue
                
                # Check for potential vulnerabilities
                is_potential_vuln, indicator = self.check_for_vulnerabilities(result["output"])
                
                if is_potential_vuln:
                    # Critic validates the finding
                    is_real, confidence, reasoning = self.critic.validate_finding(
                        command=result["command"],
                        output=result["output"],
                        potential_vuln=indicator
                    )
                    
                    if is_real and confidence >= 0.6:
                        # Real vulnerability confirmed
                        self.critical_found = True
                        self.vulnerabilities.append({
                            "iteration": iteration,
                            "command": result["command"],
                            "indicator": indicator,
                            "confidence": confidence,
                            "reasoning": reasoning,
                            "output": result["output"][:1000],
                            "validated_by": "critic_agent"
                        })
                        print(f"\n{'🚨'*20}")
                        print(f"CRITICAL VULNERABILITY CONFIRMED: {indicator}")
                        print(f"Confidence: {confidence:.0%}")
                        print(f"Reasoning: {reasoning}")
                        print(f"{'🚨'*20}\n")
                        break
                
                # Store scan results
                self.scan_history.append({
                    "iteration": iteration,
                    "command": result["command"],
                    "success": result["success"],
                    "output": result["output"][:500],
                    "timestamp": result["timestamp"]
                })
            
            if self.critical_found:
                break
        
        return self.critical_found
    
    def _scan_legacy_mode(self, domain_info: Dict[str, Any]) -> bool:
        """
        Legacy linear scanning mode (backward compatibility).
        """
        initial_context = json.dumps(domain_info, indent=2)
        iteration = 0
        
        while iteration < self.max_iterations and not self.critical_found:
            iteration += 1
            print(f"\n[Iteration {iteration}/{self.max_iterations}]")
            
            # Get next steps from AI
            if iteration == 1:
                instruction = f"""Analyze this domain reconnaissance data for {self.domain} and suggest 
the next scanning steps to identify vulnerabilities. Start with techniques that can reveal 
SQL injection, authentication bypass, or other critical issues. Suggest specific commands."""
            else:
                instruction = f"""Based on the reconnaissance so far, suggest the next most promising 
scanning step to find vulnerabilities in {self.domain}. Focus on uncovered areas. 
Provide specific executable commands."""
            
            ai_response = self.analyze_with_ai(initial_context, instruction)
            
            if not ai_response:
                print("⚠ AI analysis failed, continuing with basic scans...")
                continue
            
            print("\n[AI Analysis]")
            print(ai_response[:500])
            
            # Extract commands to execute
            commands = self.extract_commands_from_response(ai_response)
            
            if not commands:
                print("⚠ No commands extracted, generating fallback commands...")
                commands = self._generate_fallback_commands(iteration)
            
            # Execute commands
            for cmd in commands[:2]:  # Limit to 2 commands per iteration
                print(f"\n[Executing] {cmd[:80]}...")
                
                success, output = self.execute_command(cmd)
                
                if success and output:
                    print(f"[Output] {output[:200]}...")
                    
                    # Check for vulnerabilities
                    is_vuln, indicator = self.check_for_vulnerabilities(output)
                    
                    if is_vuln:
                        self.critical_found = True
                        self.vulnerabilities.append({
                            "iteration": iteration,
                            "command": cmd,
                            "indicator": indicator,
                            "output": output[:1000]
                        })
                        print(f"🚨 CRITICAL VULNERABILITY FOUND: {indicator}")
                        break
                    
                    # Store scan results
                    self.scan_history.append({
                        "iteration": iteration,
                        "command": cmd,
                        "success": success,
                        "output": output[:500],
                        "timestamp": datetime.now().isoformat()
                    })
                else:
                    print(f"[Error] {output[:100]}")
            
            if self.critical_found:
                break
        
        return self.critical_found

    def _record_browser_history(self, data: Dict[str, Any]) -> None:
        if not data:
            return
        entry: Dict[str, Any] = {
            "phase": "headless_browser",
            "timestamp": datetime.now().isoformat(),
            "status": data.get("status", "unknown"),
        }
        if data.get("reason"):
            entry["reason"] = data["reason"]
        screenshot = data.get("screenshot_path")
        if screenshot:
            entry["screenshot_path"] = screenshot
        actions = data.get("actions_performed")
        if isinstance(actions, list) and actions:
            entry["actions"] = actions[:3]
        rendered_dom = data.get("rendered_dom")
        if isinstance(rendered_dom, str) and rendered_dom:
            entry["rendered_dom_snippet"] = rendered_dom[:200]
        self.scan_history.append(entry)

    def _summarize_browser_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        summary = dict(data)
        rendered_dom = summary.get("rendered_dom")
        if isinstance(rendered_dom, str) and rendered_dom:
            max_chars = 3000
            if len(rendered_dom) > max_chars:
                summary["rendered_dom"] = rendered_dom[:max_chars] + "... [truncated]"
        console_logs = summary.get("console_logs")
        if isinstance(console_logs, list):
            summary["console_logs"] = console_logs[:10]
        forms = summary.get("forms")
        if isinstance(forms, list):
            summary["forms"] = forms[:3]
        return summary

    def _generate_fallback_commands(self, iteration: int) -> List[str]:
        """Generate fallback scanning commands with proper syntax."""
        fallback_commands = [
            f"curl -s {self.target_url} | head -50",
            f"curl -s -X OPTIONS -v {self.target_url} 2>&1 | head -20",
            f"curl -s -H 'User-Agent: Mozilla' {self.target_url} | grep -i 'error'",
        ]
        
        if iteration > 3:
            fallback_commands.extend([
                f"curl -s '{self.target_url}?id=1' 2>&1 | head -20",
                f"curl -s -X POST {self.target_url} -d 'test=1' 2>&1 | head -20",
            ])
        
        return fallback_commands[:2]

    def generate_report(self, output_file: str = None) -> str:
        """Generate a comprehensive vulnerability report."""
        if output_file is None:
            output_file = f"reports/scan_report_{self.domain.replace('.', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        
        os.makedirs(os.path.dirname(output_file) if os.path.dirname(output_file) else ".", exist_ok=True)
        
        report = []
        report.append("=" * 80)
        report.append("AUTONOMOUS AI BUG BOUNTY SCAN REPORT")
        report.append("=" * 80)
        report.append("")
        
        report.append(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"Target Domain: {self.domain}")
        report.append(f"Target URL: {self.target_url}")
        report.append(f"Total Iterations: {len([h for h in self.scan_history if 'iteration' in h])}")
        report.append(f"Vulnerabilities Found: {len(self.vulnerabilities)}")
        report.append(f"Critical Status: {'YES' if self.critical_found else 'NO'}")
        report.append("")
        
        report.append("=" * 80)
        report.append("VULNERABILITIES DISCOVERED")
        report.append("=" * 80)
        report.append("")
        
        if self.vulnerabilities:
            for idx, vuln in enumerate(self.vulnerabilities, 1):
                report.append(f"[VULNERABILITY #{idx}]")
                report.append(f"Iteration: {vuln.get('iteration', 'N/A')}")
                report.append(f"Type: {vuln.get('indicator', 'Unknown')}")
                report.append(f"Command Used: {vuln.get('command', 'N/A')}")
                report.append(f"Evidence:")
                report.append(f"{vuln.get('output', 'N/A')[:500]}")
                report.append("")
        else:
            report.append("No critical vulnerabilities discovered during this scan.")
            report.append("")
        
        report.append("=" * 80)
        report.append("SCAN TIMELINE")
        report.append("=" * 80)
        report.append("")
        
        for entry in self.scan_history[-10:]:  # Last 10 entries
            if "command" in entry:
                report.append(f"[{entry.get('timestamp', 'N/A')}] {entry.get('command', 'N/A')}")
                if entry.get('success'):
                    report.append(f"  Status: Success")
                    report.append(f"  Output: {entry.get('output', '')[:200]}")
                else:
                    report.append(f"  Status: Failed")
        
        report.append("")
        report.append("=" * 80)
        report.append("JAVASCRIPT STATIC ANALYSIS")
        report.append("=" * 80)
        report.append("")
        if self.js_analysis_results:
            js_status = self.js_analysis_results.get('status', 'unknown')
            report.append(f"Analysis Status: {js_status}")
            
            if js_status == "completed":
                total_secrets = self.js_analysis_results.get('total_secrets', 0)
                total_endpoints = self.js_analysis_results.get('total_endpoints', 0)
                
                report.append(f"JavaScript Files Analyzed: {len(self.js_analysis_results.get('analyses', []))}")
                report.append(f"Secrets Discovered: {total_secrets}")
                report.append(f"Hidden Endpoints Discovered: {total_endpoints}")
                report.append("")
                
                # List discovered secrets
                if total_secrets > 0:
                    report.append("LEAKED SECRETS:")
                    for analysis in self.js_analysis_results.get('analyses', []):
                        for secret in analysis.get('secrets', []):
                            report.append(f"  [!] {secret['type'].upper()}")
                            report.append(f"      Source: {secret['source']}")
                            report.append(f"      Line: {secret.get('line_number', 'N/A')}")
                            report.append(f"      Context: {secret['context'][:100]}...")
                            report.append("")
                
                # List discovered endpoints
                if total_endpoints > 0:
                    report.append("HIDDEN ENDPOINTS:")
                    for endpoint in self.discovered_endpoints[:20]:
                        report.append(f"  • {endpoint}")
                    if len(self.discovered_endpoints) > 20:
                        report.append(f"  ... and {len(self.discovered_endpoints) - 20} more endpoints")
                    report.append("")
        else:
            report.append("JavaScript analysis was not performed.")
        
        report.append("")
        report.append("=" * 80)
        report.append("HEADLESS BROWSER INTELLIGENCE")
        report.append("=" * 80)
        report.append("")
        if self.browser_intel:
            report.append(f"Capture Status: {self.browser_intel.get('status', 'unknown')}")
            reason = self.browser_intel.get("reason")
            if reason:
                report.append(f"Reason: {reason}")
            page_title = self.browser_intel.get("page_title")
            if page_title:
                report.append(f"Page Title: {page_title}")
            final_url = self.browser_intel.get("final_url")
            if final_url:
                report.append(f"Final URL: {final_url}")
            screenshot = self.browser_intel.get("screenshot_path")
            if screenshot:
                report.append(f"Screenshot: {screenshot}")
            actions = self.browser_intel.get("actions_performed")
            if isinstance(actions, list) and actions:
                report.append("Actions Simulated:")
                for action in actions:
                    report.append(f"  - {action}")
            forms = self.browser_intel.get("forms")
            if isinstance(forms, list) and forms:
                report.append("Observed Forms:")
                for form in forms[:3]:
                    method = form.get("method", "GET")
                    action_target = form.get("action") or "N/A"
                    report.append(f"  • Method: {method} | Action: {action_target}")
                    inputs = form.get("inputs") or []
                    for field in inputs[:5]:
                        field_type = field.get("type", "input")
                        field_name = field.get("name") or "(unnamed)"
                        report.append(f"      - {field_type}: {field_name}")
            dom_snippet = self.browser_intel.get("rendered_dom")
            if isinstance(dom_snippet, str) and dom_snippet:
                report.append("Rendered DOM Snippet:")
                snippet = dom_snippet[:500]
                if len(dom_snippet) > 500:
                    snippet += "..."
                report.append(snippet)
        else:
            if self.enable_headless_browser:
                report.append("Headless browser data unavailable.")
            else:
                report.append("Headless browser capture disabled (ENABLE_HEADLESS_BROWSER=0).")
        
        report.append("")
        report.append("=" * 80)
        report.append("RECOMMENDATIONS")
        report.append("=" * 80)
        report.append("")
        
        if self.critical_found:
            report.append("⚠️ CRITICAL VULNERABILITIES DETECTED")
            report.append("")
            report.append("Immediate Actions Required:")
            report.append("1. Isolate affected systems")
            report.append("2. Review and patch the identified vulnerability")
            report.append("3. Conduct security audit of related systems")
            report.append("4. Monitor for exploitation attempts")
        else:
            report.append("No critical vulnerabilities detected in this scan.")
            report.append("")
            report.append("Recommendations for further security improvements:")
            report.append("1. Implement Web Application Firewall (WAF)")
            report.append("2. Regular security audits and penetration testing")
            report.append("3. Keep all software and dependencies updated")
            report.append("4. Implement proper input validation and output encoding")
            report.append("5. Use security headers (HSTS, CSP, X-Frame-Options, etc.)")
        
        report.append("")
        report.append("=" * 80)
        report.append("Report Generated by: Autonomous AI Bug Bounty Agent")
        report.append("=" * 80)
        
        report_text = "\n".join(report)
        
        with open(output_file, 'w') as f:
            f.write(report_text)
        
        print(f"\n✓ Report saved to: {output_file}")
        return output_file

    def run(self, target_url: str) -> Optional[str]:
        """Main entry point for the bug bounty agent."""
        if not self.parse_url(target_url):
            return None
        
        self.scan_website()
        
        report_file = self.generate_report()
        
        return report_file


def main():
    """Main function."""
    import sys
    
    print("\n" + "="*60)
    print("AUTONOMOUS AI BUG BOUNTY AGENT")
    print("="*60)
    
    if len(sys.argv) > 1:
        target = sys.argv[1]
    else:
        target = input("\nEnter target website URL: ").strip()
    
    if not target:
        print("❌ No target provided")
        return
    
    agent = BugBountyAgent()
    report_file = agent.run(target)
    
    if report_file:
        print(f"\n✓ Scan completed!")
        print(f"✓ Report: {report_file}")
        with open(report_file, 'r') as f:
            print("\n" + f.read())
    else:
        print("❌ Scan failed")


if __name__ == "__main__":
    main()
