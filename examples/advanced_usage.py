#!/usr/bin/env python3
"""
Example 2: Advanced Usage with Custom Configuration
"""

from bug_bounty_agent import BugBountyAgent
import os


def main():
    """Run an advanced scan with custom configuration."""
    # Initialize the agent
    agent = BugBountyAgent()
    
    # Customize configuration
    agent.max_iterations = 20  # More thorough scanning
    agent.timeout = 30  # More time per command
    
    # Define targets
    targets = [
        "https://example.com",
        "https://example.org",
    ]
    
    # Scan multiple targets
    for target in targets:
        print(f"\n{'='*60}")
        print(f"Scanning: {target}")
        print(f"{'='*60}\n")
        
        report_file = agent.run(target)
        
        if report_file:
            print(f"✓ Report saved to: {report_file}")
        else:
            print(f"❌ Scan failed for {target}")


if __name__ == "__main__":
    main()
