#!/usr/bin/env python3
"""
Example 1: Basic Usage of the Bug Bounty Agent
"""

from bug_bounty_agent import BugBountyAgent


def main():
    """Run a basic scan."""
    # Initialize the agent
    agent = BugBountyAgent()
    
    # Run scan
    target = "https://example.com"
    print(f"Scanning {target}...")
    
    report_file = agent.run(target)
    
    if report_file:
        print(f"\n✓ Scan completed!")
        print(f"Report saved to: {report_file}")
        
        # Read and display the report
        with open(report_file, 'r') as f:
            print("\n" + f.read())
    else:
        print("❌ Scan failed")


if __name__ == "__main__":
    main()
