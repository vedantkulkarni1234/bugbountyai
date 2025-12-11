#!/usr/bin/env python3
"""
Example: Using the Cognitive Architecture Mode

This example demonstrates the Planner-Executor-Critic architecture
for intelligent vulnerability scanning.
"""

import os
import sys

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from bug_bounty_agent import BugBountyAgent


def main():
    """
    Demonstrates cognitive architecture scanning.
    
    The agent will:
    1. Use Planner to create strategic scanning plans
    2. Use Executor to run commands from the plan
    3. Use Critic to validate findings and reduce false positives
    """
    
    print("=" * 70)
    print("Cognitive Architecture Example")
    print("=" * 70)
    print()
    
    # Check environment
    if not os.getenv("GOOGLE_API_KEY"):
        print("❌ Error: GOOGLE_API_KEY not set")
        print("Please set your Google API key:")
        print("  export GOOGLE_API_KEY='your-api-key-here'")
        return 1
    
    # Enable cognitive mode (default is already enabled)
    os.environ["ENABLE_COGNITIVE_MODE"] = "true"
    os.environ["ENABLE_HEADLESS_BROWSER"] = "true"
    os.environ["MAX_ITERATIONS"] = "5"  # Fewer iterations for demo
    
    # Initialize agent
    print("Initializing Bug Bounty Agent with Cognitive Architecture...")
    print()
    print("Architecture Components:")
    print("  🧠 Planner Agent - Creates strategic scanning plans")
    print("  ⚡ Executor Agent - Executes commands and collects data")
    print("  🔍 Critic Agent - Validates findings (reduces false positives)")
    print("  🌐 Headless Browser - Renders JavaScript and captures DOM")
    print()
    
    try:
        agent = BugBountyAgent()
    except Exception as e:
        print(f"❌ Failed to initialize agent: {e}")
        return 1
    
    # Parse target URL
    target = "https://example.com"
    print(f"Target: {target}")
    print()
    
    if not agent.parse_url(target):
        print("❌ Failed to parse URL")
        return 1
    
    # Run cognitive scan
    print("\nStarting cognitive scan...")
    print("=" * 70)
    print()
    
    try:
        found_vulnerabilities = agent.scan_website()
        
        print()
        print("=" * 70)
        print("Scan Complete")
        print("=" * 70)
        print()
        
        if found_vulnerabilities:
            print(f"✓ Found {len(agent.vulnerabilities)} critical vulnerabilities")
            
            # Display vulnerabilities with confidence scores
            for idx, vuln in enumerate(agent.vulnerabilities, 1):
                print(f"\n[Vulnerability {idx}]")
                print(f"  Type: {vuln.get('indicator', 'Unknown')}")
                print(f"  Confidence: {vuln.get('confidence', 0)*100:.0f}%")
                print(f"  Reasoning: {vuln.get('reasoning', 'N/A')[:100]}...")
                print(f"  Command: {vuln.get('command', 'N/A')[:80]}...")
        else:
            print("✓ No critical vulnerabilities found")
            print("  (This is expected for example.com)")
        
        # Generate report
        print("\nGenerating report...")
        report_path = agent.generate_report()
        print(f"✓ Report saved to: {report_path}")
        
        print()
        print("Cognitive Architecture Statistics:")
        print(f"  • Plans created: {len(agent.planner.plans)}")
        print(f"  • Commands executed: {len(agent.executor.execution_history)}")
        print(f"  • Validations performed: {len(agent.critic.validations)}")
        
        return 0
        
    except KeyboardInterrupt:
        print("\n\nScan interrupted by user")
        return 1
    except Exception as e:
        print(f"\n❌ Scan failed: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
