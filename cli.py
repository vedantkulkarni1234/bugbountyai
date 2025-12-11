#!/usr/bin/env python3
"""
Command-line interface for the Autonomous AI Bug Bounty Agent.
"""

import sys
import argparse
from pathlib import Path
from bug_bounty_agent import BugBountyAgent


def parse_arguments():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Autonomous AI-powered Bug Bounty Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python cli.py https://example.com
  python cli.py example.com --output custom_report.txt
  python cli.py https://target.app --max-iterations 20
        """
    )
    
    parser.add_argument(
        "target",
        help="Target website URL (with or without https://)"
    )
    
    parser.add_argument(
        "-o", "--output",
        help="Output file path for the report",
        default=None
    )
    
    parser.add_argument(
        "-i", "--max-iterations",
        type=int,
        help="Maximum scanning iterations (default: 15)",
        default=15
    )
    
    parser.add_argument(
        "-t", "--timeout",
        type=int,
        help="Command execution timeout in seconds (default: 10)",
        default=10
    )
    
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output"
    )
    
    parser.add_argument(
        "--headless-mode",
        choices=["auto", "on", "off"],
        default="auto",
        help=(
            "Control the Playwright-powered headless browser reconnaissance. "
            "Use 'on' to force enable, 'off' to disable, or 'auto' to respect the .env setting."
        )
    )
    
    return parser.parse_args()


def main():
    """Main CLI entry point."""
    args = parse_arguments()
    
    print("\n" + "="*70)
    print("  AUTONOMOUS AI BUG BOUNTY AGENT v1.0")
    print("="*70 + "\n")
    
    try:
        agent = BugBountyAgent()
        
        # Override settings if provided
        if args.max_iterations:
            agent.max_iterations = args.max_iterations
        if args.timeout:
            agent.timeout = args.timeout
        if args.headless_mode != "auto":
            agent.enable_headless_browser = args.headless_mode == "on"
        
        if args.verbose:
            print(f"[*] Configuration:")
            print(f"    - Target: {args.target}")
            print(f"    - Max Iterations: {agent.max_iterations}")
            print(f"    - Timeout: {agent.timeout}s")
            headless_state = "enabled" if agent.enable_headless_browser else "disabled"
            print(f"    - Headless Browser: {headless_state} (mode={args.headless_mode})")
            print()
        
        # Run the scan
        report_file = agent.run(args.target)
        
        if report_file:
            print(f"\n{'='*70}")
            print(f"✓ Scan Successfully Completed!")
            print(f"{'='*70}")
            print(f"\n📄 Report saved to: {report_file}\n")
            
            # Display report if verbose
            if args.verbose:
                print("\n" + "="*70)
                print("REPORT CONTENT:")
                print("="*70 + "\n")
                with open(report_file, 'r') as f:
                    print(f.read())
        else:
            print("\n❌ Scan failed")
            sys.exit(1)
    
    except KeyboardInterrupt:
        print("\n\n❌ Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
