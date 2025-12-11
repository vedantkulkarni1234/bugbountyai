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
from typing import Dict, List, Tuple, Optional
from urllib.parse import urlparse

import requests
from openai import OpenAI
from dotenv import load_dotenv

try:
    import google.generativeai as genai
except ImportError:
    genai = None


class BugBountyAgent:
    """
    An autonomous AI-powered bug bounty scanning agent that:
    1. Takes a website URL
    2. Performs reconnaissance using curl and other tools
    3. Uses Google's Gemini to analyze outputs and generate next steps
    4. Iteratively searches for vulnerabilities
    5. Generates a comprehensive report
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
        
        self.target_url = None
        self.domain = None
        self.vulnerabilities = []
        self.scan_history = []
        self.critical_found = False
        
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
        """Execute the main scanning loop."""
        print(f"\n{'='*60}")
        print(f"Starting autonomous scan of {self.domain}")
        print(f"{'='*60}\n")
        
        # Phase 1: Initial reconnaissance
        domain_info = self.get_domain_info()
        self.scan_history.append({
            "phase": "reconnaissance",
            "timestamp": datetime.now().isoformat(),
            "data": domain_info
        })
        
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
