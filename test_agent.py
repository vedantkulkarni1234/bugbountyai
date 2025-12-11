#!/usr/bin/env python3
"""
Test cases for the Bug Bounty Agent.
"""

import unittest
from unittest.mock import patch, MagicMock
from bug_bounty_agent import BugBountyAgent
from utils import URLValidator, CommandBuilder, VulnerabilityAnalyzer


class TestURLValidator(unittest.TestCase):
    """Test URL validation utilities."""
    
    def test_validate_url_with_protocol(self):
        """Test validation of URL with protocol."""
        valid, normalized, domain = URLValidator.validate_and_normalize("https://example.com")
        self.assertTrue(valid)
        self.assertEqual(domain, "example.com")
    
    def test_validate_url_without_protocol(self):
        """Test validation of URL without protocol."""
        valid, normalized, domain = URLValidator.validate_and_normalize("example.com")
        self.assertTrue(valid)
        self.assertEqual(domain, "example.com")
    
    def test_invalid_url(self):
        """Test validation of invalid URL."""
        valid, _, _ = URLValidator.validate_and_normalize("not a valid url")
        self.assertFalse(valid)
    
    def test_is_valid_domain(self):
        """Test domain validation."""
        self.assertTrue(URLValidator.is_valid_domain("example.com"))
        self.assertTrue(URLValidator.is_valid_domain("sub.example.co.uk"))
        self.assertFalse(URLValidator.is_valid_domain("invalid_domain!"))


class TestCommandBuilder(unittest.TestCase):
    """Test command building utilities."""
    
    def test_build_curl_headers(self):
        """Test curl command building."""
        cmd = CommandBuilder.build_curl_headers("https://example.com")
        self.assertIn("curl", cmd)
        self.assertIn("example.com", cmd)
    
    def test_sql_injection_tests(self):
        """Test SQL injection command generation."""
        tests = CommandBuilder.build_sql_injection_test("https://example.com")
        self.assertGreater(len(tests), 0)
        self.assertTrue(all("curl" in test for test in tests))


class TestVulnerabilityAnalyzer(unittest.TestCase):
    """Test vulnerability analysis utilities."""
    
    def test_detect_sql_injection(self):
        """Test SQL injection detection."""
        output = "Error in your SQL syntax near 'OR 1=1'"
        is_vuln, types = VulnerabilityAnalyzer.analyze(output)
        self.assertTrue(is_vuln)
        self.assertIn('sql_injection', types)
    
    def test_detect_rce(self):
        """Test RCE detection."""
        output = "Remote Code Execution vulnerability found"
        is_vuln, types = VulnerabilityAnalyzer.analyze(output)
        self.assertTrue(is_vuln)
    
    def test_no_vulnerability(self):
        """Test clean output."""
        output = "Normal application response"
        is_vuln, types = VulnerabilityAnalyzer.analyze(output)
        self.assertFalse(is_vuln)
    
    def test_false_positive_word_critical(self):
        """Test that 'critical' alone doesn't trigger false positive."""
        output = "This is a critical update for your system"
        is_vuln, types = VulnerabilityAnalyzer.analyze(output)
        self.assertFalse(is_vuln)
    
    def test_false_positive_word_vulnerability(self):
        """Test that 'vulnerability' alone doesn't trigger without context."""
        output = "We discussed vulnerability scanning techniques"
        is_vuln, types = VulnerabilityAnalyzer.analyze(output)
        self.assertFalse(is_vuln)


class TestBugBountyAgent(unittest.TestCase):
    """Test BugBountyAgent class."""
    
    def setUp(self):
        """Set up test fixtures."""
        with patch.dict('os.environ', {'GOOGLE_API_KEY': 'test-key'}):
            self.agent = BugBountyAgent()
    
    def test_parse_url_valid(self):
        """Test URL parsing with valid URL."""
        result = self.agent.parse_url("https://example.com")
        self.assertTrue(result)
        self.assertEqual(self.agent.domain, "example.com")
    
    def test_parse_url_invalid(self):
        """Test URL parsing with invalid URL."""
        result = self.agent.parse_url("not a url")
        self.assertFalse(result)
    
    def test_check_for_vulnerabilities_positive(self):
        """Test vulnerability checking with vulnerable output."""
        output = "SQL error in your syntax"
        is_vuln, indicator = self.agent.check_for_vulnerabilities(output)
        self.assertTrue(is_vuln)
    
    def test_check_for_vulnerabilities_negative(self):
        """Test vulnerability checking with clean output."""
        output = "Normal 200 response OK successful"
        is_vuln, indicator = self.agent.check_for_vulnerabilities(output)
        self.assertFalse(is_vuln)
    
    def test_false_positive_critical_word_alone(self):
        """Test that 'critical' word alone doesn't trigger vulnerability detection."""
        output = "This is a critical security update"
        is_vuln, indicator = self.agent.check_for_vulnerabilities(output)
        self.assertFalse(is_vuln)
    
    def test_false_positive_vulnerability_word_alone(self):
        """Test that 'vulnerability' word alone doesn't trigger without evidence."""
        output = "vulnerability assessment in progress"
        is_vuln, indicator = self.agent.check_for_vulnerabilities(output)
        self.assertFalse(is_vuln)
    
    def test_false_positive_xss_word_alone(self):
        """Test that 'xss' word alone doesn't trigger without payload evidence."""
        output = "XSS testing framework installed"
        is_vuln, indicator = self.agent.check_for_vulnerabilities(output)
        self.assertFalse(is_vuln)
    
    def test_real_sql_injection_error(self):
        """Test genuine SQL error detection."""
        output = "Error in your SQL syntax near 'OR 1=1' at line 5"
        is_vuln, indicator = self.agent.check_for_vulnerabilities(output)
        self.assertTrue(is_vuln)
    
    def test_real_path_traversal(self):
        """Test path traversal evidence detection."""
        output = "File contents: root:x:0:0:/root:/bin/bash"
        is_vuln, indicator = self.agent.check_for_vulnerabilities(output)
        self.assertTrue(is_vuln)
    
    def test_execute_command_success(self):
        """Test successful command execution."""
        success, output = self.agent.execute_command("echo 'test'")
        self.assertTrue(success)
        self.assertIn("test", output)
    
    def test_execute_command_timeout(self):
        """Test command timeout."""
        success, output = self.agent.execute_command("sleep 100")
        self.assertFalse(success)
    
    @patch('bug_bounty_agent.HeadlessBrowser')
    def test_headless_browser_skipped_when_disabled(self, MockBrowser):
        """Headless browser should skip when disabled."""
        mock_instance = MockBrowser.return_value
        mock_instance.is_available.return_value = True
        with patch.dict('os.environ', {'GOOGLE_API_KEY': 'test-key'}):
            agent = BugBountyAgent()
        agent.enable_headless_browser = False
        agent.target_url = "https://example.com"
        result = agent.gather_browser_intel()
        self.assertEqual(result.get("status"), "skipped")
        mock_instance.collect_page_data.assert_not_called()
    
    @patch('bug_bounty_agent.HeadlessBrowser')
    def test_headless_browser_collects_when_available(self, MockBrowser):
        """Headless browser should collect data when enabled and available."""
        mock_instance = MockBrowser.return_value
        mock_instance.is_available.return_value = True
        mock_instance.collect_page_data.return_value = {
            "status": "captured",
            "rendered_dom": "<html></html>",
            "actions_performed": ["scrolled_to_bottom"],
        }
        with patch.dict('os.environ', {'GOOGLE_API_KEY': 'test-key'}):
            agent = BugBountyAgent()
        agent.enable_headless_browser = True
        agent.target_url = "https://example.com"
        data = agent.gather_browser_intel()
        self.assertEqual(data.get("status"), "captured")
        mock_instance.collect_page_data.assert_called_once_with("https://example.com")
        self.assertTrue(any(entry.get("phase") == "headless_browser" for entry in agent.scan_history))


class TestIntegration(unittest.TestCase):
    """Integration tests."""
    
    @patch('bug_bounty_agent.BugBountyAgent.analyze_with_ai')
    def test_scan_workflow(self, mock_ai):
        """Test the overall scanning workflow."""
        mock_ai.return_value = "curl -s https://example.com"

        with patch.dict('os.environ', {'GOOGLE_API_KEY': 'test-key'}):
            agent = BugBountyAgent()
            agent.max_iterations = 1

            # This would normally scan, but we're mocking the AI
            result = agent.parse_url("https://example.com")
            self.assertTrue(result)


def run_tests():
    """Run all tests."""
    unittest.main(argv=[''], exit=False, verbosity=2)


if __name__ == "__main__":
    run_tests()
