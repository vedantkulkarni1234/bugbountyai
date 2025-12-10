#!/usr/bin/env python3
"""
Example 4: Batch Scanning Multiple Targets
"""

import json
from datetime import datetime
from bug_bounty_agent import BugBountyAgent


class BatchScanner:
    """Batch scanning utility for multiple targets."""
    
    def __init__(self):
        self.results = []
        self.agent = BugBountyAgent()
    
    def scan_targets(self, targets: list) -> dict:
        """Scan multiple targets and compile results."""
        for idx, target in enumerate(targets, 1):
            print(f"\n[{idx}/{len(targets)}] Scanning: {target}")
            print("=" * 60)
            
            try:
                report_file = self.agent.run(target)
                
                if report_file:
                    self.results.append({
                        "target": target,
                        "status": "completed",
                        "report": report_file,
                        "vulnerabilities": len(self.agent.vulnerabilities),
                        "timestamp": datetime.now().isoformat()
                    })
                    print(f"✓ Report: {report_file}")
                else:
                    self.results.append({
                        "target": target,
                        "status": "failed",
                        "timestamp": datetime.now().isoformat()
                    })
                    print(f"❌ Scan failed")
            
            except Exception as e:
                print(f"❌ Error scanning {target}: {e}")
                self.results.append({
                    "target": target,
                    "status": "error",
                    "error": str(e),
                    "timestamp": datetime.now().isoformat()
                })
        
        return self._generate_summary()
    
    def _generate_summary(self) -> dict:
        """Generate batch scan summary."""
        summary = {
            "total_targets": len(self.results),
            "completed": sum(1 for r in self.results if r["status"] == "completed"),
            "failed": sum(1 for r in self.results if r["status"] == "failed"),
            "errors": sum(1 for r in self.results if r["status"] == "error"),
            "total_vulnerabilities": sum(
                r.get("vulnerabilities", 0) for r in self.results if r["status"] == "completed"
            ),
            "results": self.results
        }
        return summary
    
    def save_summary(self, output_file: str = "batch_results.json"):
        """Save batch results to JSON."""
        with open(output_file, 'w') as f:
            json.dump(self._generate_summary(), f, indent=2)
        print(f"\n✓ Batch results saved to: {output_file}")


def main():
    """Run batch scanning."""
    targets = [
        "https://example.com",
        "https://example.org",
        "https://example.net",
    ]
    
    scanner = BatchScanner()
    
    print("\n" + "=" * 60)
    print("BATCH SCANNING")
    print("=" * 60)
    print(f"Targets: {len(targets)}")
    
    # Run scans
    results = scanner.scan_targets(targets)
    
    # Print summary
    print("\n" + "=" * 60)
    print("BATCH SCAN SUMMARY")
    print("=" * 60)
    print(f"Total Targets: {results['total_targets']}")
    print(f"Completed: {results['completed']}")
    print(f"Failed: {results['failed']}")
    print(f"Errors: {results['errors']}")
    print(f"Total Vulnerabilities Found: {results['total_vulnerabilities']}")
    
    # Save results
    scanner.save_summary()


if __name__ == "__main__":
    main()
