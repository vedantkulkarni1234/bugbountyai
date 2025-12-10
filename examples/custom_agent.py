#!/usr/bin/env python3
"""
Example 3: Custom Agent with Extended Functionality
"""

from bug_bounty_agent import BugBountyAgent
from typing import List


class CustomBugBountyAgent(BugBountyAgent):
    """
    Extended agent with custom scanning strategies.
    """
    
    def _generate_fallback_commands(self, iteration: int) -> List[str]:
        """
        Generate custom fallback commands based on iteration.
        """
        # Early iterations: basic reconnaissance
        if iteration <= 3:
            return [
                f"curl -s -I {self.target_url}",
                f"curl -s -X OPTIONS -v {self.target_url} 2>&1",
            ]
        
        # Middle iterations: focused vulnerability testing
        elif iteration <= 10:
            return [
                f"curl -s -X POST {self.target_url} -d 'test=1' 2>&1 | head -20",
                f"curl -s {self.target_url}' OR '1'='1' 2>&1 | head -20",
            ]
        
        # Late iterations: deep scanning
        else:
            return [
                f"curl -s -H 'X-Original-URL: /admin' {self.target_url} 2>&1",
                f"curl -s -H 'X-Forwarded-For: 127.0.0.1' {self.target_url} 2>&1",
            ]
    
    def get_domain_info(self) -> dict:
        """
        Override to add custom reconnaissance.
        """
        info = super().get_domain_info()
        
        # Add custom reconnaissance
        success, output = self.execute_command(f"host {self.domain} 2>/dev/null")
        if success:
            info["host_lookup"] = output[:200]
        
        return info


def main():
    """Run scan with custom agent."""
    agent = CustomBugBountyAgent()
    agent.max_iterations = 15
    
    target = "https://example.com"
    print(f"Scanning {target} with custom agent...")
    
    report_file = agent.run(target)
    
    if report_file:
        print(f"\n✓ Scan completed!")
        print(f"Report saved to: {report_file}")


if __name__ == "__main__":
    main()
