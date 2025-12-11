"""
Cognitive Architecture: Planner-Executor-Critic Agents
Implements a three-agent system for intelligent vulnerability scanning.
"""

import json
import re
from datetime import datetime
from typing import Any, Dict, List, Tuple, Optional

try:
    import google.generativeai as genai
except ImportError:
    genai = None


class PlannerAgent:
    """
    The Planner Agent analyzes target information and creates a strategic
    scanning plan. It breaks down the target into phases and prioritizes
    vulnerability testing based on reconnaissance data.
    """
    
    def __init__(self, model):
        """
        Initialize the Planner Agent.
        
        Args:
            model: Google Gemini AI model instance
        """
        self.model = model
        self.plans = []
    
    def create_scanning_plan(
        self, 
        domain: str, 
        domain_info: Dict[str, Any], 
        browser_data: Dict[str, Any],
        iteration: int,
        discovered_endpoints: List[str] = None
    ) -> Dict[str, Any]:
        """
        Analyze the target and create a strategic scanning plan.
        
        Args:
            domain: Target domain
            domain_info: Reconnaissance data (headers, DNS, etc.)
            browser_data: Headless browser intelligence
            iteration: Current iteration number
            discovered_endpoints: Endpoints discovered from JS analysis
            
        Returns:
            Dictionary containing scanning strategy with phases and priorities
        """
        print(f"\n[Planner Agent] Creating strategic plan for {domain}...")
        
        # Prepare context for AI planning
        context = self._prepare_planning_context(domain_info, browser_data, discovered_endpoints)
        
        # Create strategic plan based on iteration phase
        if iteration == 1:
            plan = self._create_initial_plan(domain, context, discovered_endpoints)
        elif iteration <= 5:
            plan = self._create_exploration_plan(domain, context, iteration, discovered_endpoints)
        else:
            plan = self._create_deep_scan_plan(domain, context, iteration, discovered_endpoints)
        
        self.plans.append(plan)
        self._display_plan(plan)
        
        return plan
    
    def _prepare_planning_context(
        self, 
        domain_info: Dict[str, Any], 
        browser_data: Dict[str, Any],
        discovered_endpoints: List[str] = None
    ) -> str:
        """Prepare context for AI planning."""
        context_parts = []
        
        # HTTP headers analysis
        if "http_headers" in domain_info:
            context_parts.append("HTTP Headers:")
            context_parts.append(domain_info["http_headers"][:500])
        
        # Browser intelligence
        if browser_data and browser_data.get("status") == "captured":
            context_parts.append("\nBrowser Intelligence:")
            context_parts.append(f"- Page Title: {browser_data.get('page_title', 'N/A')}")
            context_parts.append(f"- Forms Found: {len(browser_data.get('forms', []))}")
            
            forms = browser_data.get('forms', [])
            if forms:
                context_parts.append("- Form Details:")
                for form in forms[:3]:
                    method = form.get('method', 'GET')
                    action = form.get('action', 'N/A')
                    inputs = form.get('inputs', [])
                    context_parts.append(f"  • {method} form with {len(inputs)} inputs → {action}")
            
            dom = browser_data.get('rendered_dom', '')
            if dom:
                context_parts.append(f"- DOM Size: {len(dom)} characters")
        
        # JavaScript analysis results
        if domain_info.get("js_analysis"):
            js_info = domain_info["js_analysis"]
            context_parts.append("\nJavaScript Analysis:")
            context_parts.append(f"- Secrets Found: {js_info.get('secrets_found', 0)}")
            context_parts.append(f"- Hidden Endpoints Found: {js_info.get('endpoints_found', 0)}")
        
        # Discovered endpoints
        if discovered_endpoints:
            context_parts.append("\nDiscovered Hidden Endpoints (from JS):")
            for endpoint in discovered_endpoints[:5]:
                context_parts.append(f"  • {endpoint}")
            if len(discovered_endpoints) > 5:
                context_parts.append(f"  ... and {len(discovered_endpoints) - 5} more")
        
        return "\n".join(context_parts)
    
    def _create_initial_plan(self, domain: str, context: str, discovered_endpoints: List[str] = None) -> Dict[str, Any]:
        """Create initial reconnaissance plan."""
        endpoint_context = ""
        if discovered_endpoints:
            endpoint_context = f"\n\nIMPORTANT: Hidden API endpoints discovered from JavaScript analysis:\n"
            for ep in discovered_endpoints[:3]:
                endpoint_context += f"- {ep}\n"
            endpoint_context += "Prioritize testing these endpoints for vulnerabilities!"
        
        prompt = f"""You are an expert penetration testing strategist. Analyze this target and create a focused scanning strategy.

Target: {domain}

Reconnaissance Data:
{context}{endpoint_context}

Create a strategic plan with:
1. Target Classification (technology stack, framework, CMS)
2. Top 3 Vulnerability Priorities (based on reconnaissance)
3. Specific Commands (2-3 commands to test the highest priority vulnerabilities)

Focus on finding critical vulnerabilities like SQL injection, authentication bypass, RCE, SSRF, XXE, XSS.
Be specific and actionable."""

        try:
            response = self.model.generate_content(
                prompt,
                generation_config=genai.types.GenerationConfig(
                    temperature=0.7,
                    max_output_tokens=800
                )
            )
            
            ai_plan = response.text
            
        except Exception as e:
            print(f"⚠ Planner AI error: {e}")
            ai_plan = "Fallback: Test for SQL injection, XSS, and authentication issues."
        
        return {
            "phase": "initial_reconnaissance",
            "iteration": 1,
            "strategy": ai_plan,
            "priorities": self._extract_priorities(ai_plan),
            "commands": self._extract_commands_from_plan(ai_plan, domain),
            "timestamp": datetime.now().isoformat()
        }
    
    def _create_exploration_plan(
        self, 
        domain: str, 
        context: str, 
        iteration: int,
        discovered_endpoints: List[str] = None
    ) -> Dict[str, Any]:
        """Create exploration phase plan."""
        endpoint_hint = ""
        if discovered_endpoints and iteration <= 3:
            endpoint_hint = f"\n\nTest these discovered endpoints:\n"
            for ep in discovered_endpoints[:2]:
                endpoint_hint += f"- {ep}\n"
        
        prompt = f"""Continue vulnerability scanning strategy for {domain} (Iteration {iteration}).

Previous findings summary:
{context[:1000]}{endpoint_hint}

What should we test next? Suggest 2-3 specific scanning commands focusing on:
- Different attack vectors than previous iterations
- Areas not yet covered
- Critical vulnerabilities (SQLi, RCE, SSRF, auth bypass)

Be specific and provide exact commands."""

        try:
            response = self.model.generate_content(
                prompt,
                generation_config=genai.types.GenerationConfig(
                    temperature=0.8,
                    max_output_tokens=600
                )
            )
            ai_plan = response.text
        except Exception:
            ai_plan = f"Test additional endpoints and parameters on {domain}"
        
        return {
            "phase": "exploration",
            "iteration": iteration,
            "strategy": ai_plan,
            "priorities": self._extract_priorities(ai_plan),
            "commands": self._extract_commands_from_plan(ai_plan, domain),
            "timestamp": datetime.now().isoformat()
        }
    
    def _create_deep_scan_plan(
        self, 
        domain: str, 
        context: str, 
        iteration: int,
        discovered_endpoints: List[str] = None
    ) -> Dict[str, Any]:
        """Create deep scanning plan."""
        commands = [
            f"curl -s '{domain}?id=1' UNION SELECT version()--'",
            f"curl -s -X POST {domain} -d 'cmd=whoami'"
        ]
        
        # Add discovered endpoint testing
        if discovered_endpoints:
            for endpoint in discovered_endpoints[:2]:
                commands.append(f"curl -s -I {endpoint}")
        
        return {
            "phase": "deep_scan",
            "iteration": iteration,
            "strategy": f"Deep vulnerability testing on {domain}",
            "priorities": ["RCE", "SQL Injection", "SSRF"],
            "commands": commands,
            "timestamp": datetime.now().isoformat()
        }
    
    def _extract_priorities(self, plan_text: str) -> List[str]:
        """Extract vulnerability priorities from plan text."""
        priorities = []
        vuln_keywords = [
            'sql injection', 'sqli', 'xss', 'cross-site scripting',
            'rce', 'remote code execution', 'ssrf', 'authentication bypass',
            'xxe', 'csrf', 'path traversal', 'command injection'
        ]
        
        plan_lower = plan_text.lower()
        for keyword in vuln_keywords:
            if keyword in plan_lower:
                priorities.append(keyword.upper())
        
        return priorities[:5]
    
    def _extract_commands_from_plan(self, plan_text: str, domain: str) -> List[str]:
        """Extract executable commands from plan text."""
        commands = []
        allowed_prefixes = ['curl', 'nmap', 'ffuf', 'sqlmap', 'nikto', 'wget']
        
        lines = plan_text.split('\n')
        for line in lines:
            line = line.strip()
            
            # Check if line starts with allowed command
            for prefix in allowed_prefixes:
                if line.startswith(f"{prefix} "):
                    # Safety check
                    if not any(danger in line.lower() for danger in ['rm -', 'dd if=', 'mkfs']):
                        commands.append(line)
                    break
            
            # Also check if command appears after common prefixes like "run:", "try:", etc.
            for separator in ['run:', 'try:', 'execute:', 'test:']:
                if separator in line.lower():
                    # Extract text after separator
                    parts = line.split(separator, 1)
                    if len(parts) == 2:
                        potential_cmd = parts[1].strip()
                        for prefix in allowed_prefixes:
                            if potential_cmd.startswith(f"{prefix} "):
                                # Safety check
                                if not any(danger in potential_cmd.lower() for danger in ['rm -', 'dd if=', 'mkfs']):
                                    commands.append(potential_cmd)
                                break
        
        return commands[:3]
    
    def _display_plan(self, plan: Dict[str, Any]):
        """Display the scanning plan."""
        print(f"  Phase: {plan['phase']}")
        print(f"  Priorities: {', '.join(plan.get('priorities', []))}")
        print(f"  Commands: {len(plan.get('commands', []))} generated")


class ExecutorAgent:
    """
    The Executor Agent runs the scanning commands from the Planner's strategy.
    It executes commands safely and collects output for analysis.
    """
    
    def __init__(self, execute_command_fn):
        """
        Initialize the Executor Agent.
        
        Args:
            execute_command_fn: Function to execute shell commands
        """
        self.execute_command = execute_command_fn
        self.execution_history = []
    
    def execute_plan(self, plan: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Execute the commands from a scanning plan.
        
        Args:
            plan: Scanning plan from PlannerAgent
            
        Returns:
            List of execution results with outputs
        """
        print(f"\n[Executor Agent] Executing {len(plan.get('commands', []))} commands...")
        
        commands = plan.get('commands', [])
        if not commands:
            commands = self._generate_fallback_commands(plan)
        
        results = []
        for idx, cmd in enumerate(commands[:3], 1):
            print(f"  [{idx}/{len(commands[:3])}] Running: {cmd[:60]}...")
            
            success, output = self.execute_command(cmd)
            
            result = {
                "command": cmd,
                "success": success,
                "output": output,
                "output_length": len(output),
                "timestamp": datetime.now().isoformat()
            }
            
            results.append(result)
            self.execution_history.append(result)
            
            if success:
                print(f"      ✓ Success ({len(output)} chars)")
            else:
                print(f"      ✗ Failed: {output[:50]}")
        
        return results
    
    def _generate_fallback_commands(self, plan: Dict[str, Any]) -> List[str]:
        """Generate fallback commands if plan has none."""
        phase = plan.get('phase', 'exploration')
        
        if phase == "initial_reconnaissance":
            return [
                "curl -s -I -L {url}",
                "curl -s {url} | head -100"
            ]
        else:
            return [
                "curl -s {url}?test=1",
                "curl -s -X OPTIONS {url}"
            ]


class CriticAgent:
    """
    The Critic Agent validates vulnerability findings to reduce false positives.
    It uses AI analysis to determine if a finding is a real vulnerability or not.
    """
    
    def __init__(self, model):
        """
        Initialize the Critic Agent.
        
        Args:
            model: Google Gemini AI model instance
        """
        self.model = model
        self.validations = []
    
    def validate_finding(
        self, 
        command: str, 
        output: str, 
        potential_vuln: str
    ) -> Tuple[bool, float, str]:
        """
        Validate if a potential vulnerability is real or a false positive.
        
        Args:
            command: The command that was executed
            output: The output from the command
            potential_vuln: The type of potential vulnerability detected
            
        Returns:
            Tuple of (is_real_vulnerability, confidence_score, reasoning)
        """
        print(f"\n[Critic Agent] Validating potential {potential_vuln}...")
        
        # First pass: Pattern-based validation
        pattern_result = self._pattern_based_validation(output, potential_vuln)
        if not pattern_result["has_evidence"]:
            print(f"  ✗ Rejected: Insufficient evidence")
            return False, 0.0, "Pattern validation failed - no concrete evidence"
        
        # Second pass: AI-based validation for higher confidence
        ai_result = self._ai_based_validation(command, output, potential_vuln)
        
        is_valid = ai_result["is_valid"]
        confidence = ai_result["confidence"]
        reasoning = ai_result["reasoning"]
        
        validation_record = {
            "potential_vuln": potential_vuln,
            "is_valid": is_valid,
            "confidence": confidence,
            "reasoning": reasoning,
            "timestamp": datetime.now().isoformat()
        }
        self.validations.append(validation_record)
        
        if is_valid:
            print(f"  ✓ Confirmed: {reasoning} (confidence: {confidence:.0%})")
        else:
            print(f"  ✗ Rejected: {reasoning}")
        
        return is_valid, confidence, reasoning
    
    def _pattern_based_validation(
        self, 
        output: str, 
        vuln_type: str
    ) -> Dict[str, Any]:
        """
        First-pass validation using strong pattern matching.
        """
        output_lower = output.lower()
        
        # Evidence patterns for different vulnerability types
        evidence_patterns = {
            'sql': [
                r'mysql.*error',
                r'syntax error.*near',
                r'unclosed quotation',
                r'you have an error.*sql',
            ],
            'rce': [
                r'uid=\d+.*gid=\d+',
                r'root:.*:/bin/',
                r'command.*executed',
            ],
            'xss': [
                r'<script>.*</script>',
                r'javascript:',
                r'onerror=.*alert',
            ],
            'ssrf': [
                r'127\.0\.0\.1',
                r'localhost',
                r'internal.*request',
            ],
            'path_traversal': [
                r'/etc/passwd',
                r'root:x:0:0',
                r'\.\./\.\./\.\.',
            ]
        }
        
        # Find matching patterns
        for key, patterns in evidence_patterns.items():
            if key in vuln_type.lower():
                for pattern in patterns:
                    if re.search(pattern, output_lower):
                        return {
                            "has_evidence": True,
                            "matched_pattern": pattern
                        }
        
        return {"has_evidence": False}
    
    def _ai_based_validation(
        self, 
        command: str, 
        output: str, 
        vuln_type: str
    ) -> Dict[str, Any]:
        """
        Second-pass validation using AI analysis.
        """
        prompt = f"""You are a security expert analyzing potential vulnerabilities.

Command executed: {command}

Output received:
{output[:2000]}

Potential vulnerability type: {vuln_type}

Question: Is this a REAL vulnerability or a false positive?

Analyze the output carefully. Consider:
1. Is there concrete evidence of exploitation?
2. Are there actual error messages that indicate vulnerability?
3. Could this be normal application behavior?
4. Is this just a mention of the vulnerability type in documentation?

Respond with JSON:
{{
    "is_real_vulnerability": true/false,
    "confidence": 0.0 to 1.0,
    "reasoning": "brief explanation"
}}"""

        try:
            response = self.model.generate_content(
                prompt,
                generation_config=genai.types.GenerationConfig(
                    temperature=0.3,
                    max_output_tokens=300
                )
            )
            
            # Try to extract JSON from response
            response_text = response.text
            json_match = re.search(r'\{[^}]+\}', response_text, re.DOTALL)
            
            if json_match:
                result = json.loads(json_match.group())
                return {
                    "is_valid": result.get("is_real_vulnerability", False),
                    "confidence": result.get("confidence", 0.5),
                    "reasoning": result.get("reasoning", "AI analysis completed")
                }
            
            # Fallback: Parse response text
            is_valid = "true" in response_text.lower() or "real vulnerability" in response_text.lower()
            return {
                "is_valid": is_valid,
                "confidence": 0.6,
                "reasoning": response_text[:200]
            }
            
        except Exception as e:
            print(f"  ⚠ Critic AI error: {e}")
            # Fallback to pattern-based decision
            return {
                "is_valid": True,  # Conservative: allow pattern matches through
                "confidence": 0.5,
                "reasoning": "AI validation unavailable, relying on pattern match"
            }
