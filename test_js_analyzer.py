#!/usr/bin/env python3
"""
Simple tests for JavaScript Static Analyzer
"""

from js_static_analyzer import JSStaticAnalyzer


def test_secret_detection():
    """Test that secret patterns are detected correctly."""
    analyzer = JSStaticAnalyzer()
    
    # Test AWS key detection
    js_content = """
    const config = {
        aws: {
            accessKeyId: "AKIAIOSFODNN7PRODUCTIONKEY",
            secretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYPRODUCTIONKEY"
        }
    };
    """
    
    secrets = analyzer.scan_for_secrets(js_content, "https://example.com/test.js")
    
    print("Test: AWS Key Detection")
    print(f"  Found {len(secrets)} secret(s)")
    for secret in secrets:
        print(f"  - {secret['type']}: {secret['value'][:20]}...")
    
    assert len(secrets) >= 1, "Should detect at least one AWS key"
    print("  ✓ PASSED\n")


def test_google_api_key_detection():
    """Test Google API key detection."""
    analyzer = JSStaticAnalyzer()
    
    js_content = """
    const GOOGLE_MAPS_KEY = "AIzaSyD1234567890abcdefghijklmnopqrstuv";
    """
    
    secrets = analyzer.scan_for_secrets(js_content, "https://example.com/maps.js")
    
    print("Test: Google API Key Detection")
    print(f"  Found {len(secrets)} secret(s)")
    for secret in secrets:
        print(f"  - {secret['type']}: {secret['value'][:20]}...")
    
    assert len(secrets) >= 1, "Should detect Google API key"
    print("  ✓ PASSED\n")


def test_jwt_detection():
    """Test JWT token detection."""
    analyzer = JSStaticAnalyzer()
    
    js_content = """
    const token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    """
    
    secrets = analyzer.scan_for_secrets(js_content, "https://example.com/auth.js")
    
    print("Test: JWT Token Detection")
    print(f"  Found {len(secrets)} secret(s)")
    for secret in secrets:
        print(f"  - {secret['type']}: {secret['value'][:30]}...")
    
    assert len(secrets) >= 1, "Should detect JWT token"
    print("  ✓ PASSED\n")


def test_endpoint_discovery():
    """Test API endpoint discovery."""
    analyzer = JSStaticAnalyzer()
    
    js_content = """
    const API_ROUTES = {
        users: "/api/v1/users",
        admin: "/api/v1/admin/dashboard",
        internal: "/internal/metrics",
        graphql: "/graphql"
    };
    """
    
    endpoints = analyzer.scan_for_endpoints(js_content, "https://example.com")
    
    print("Test: Endpoint Discovery")
    print(f"  Found {len(endpoints)} endpoint(s)")
    for ep in endpoints:
        print(f"  - {ep['endpoint']}")
    
    assert len(endpoints) >= 3, "Should discover multiple endpoints"
    print("  ✓ PASSED\n")


def test_placeholder_filtering():
    """Test that placeholders are filtered out."""
    analyzer = JSStaticAnalyzer()
    
    js_content = """
    // Example configuration - replace with your keys
    const config = {
        apiKey: "YOUR_API_KEY_HERE",
        secret: "example-secret-123"
    };
    """
    
    secrets = analyzer.scan_for_secrets(js_content, "https://example.com/config.js")
    
    print("Test: Placeholder Filtering")
    print(f"  Found {len(secrets)} secret(s) (should be 0)")
    
    assert len(secrets) == 0, "Should filter out placeholder values"
    print("  ✓ PASSED\n")


def test_script_url_extraction():
    """Test script URL extraction from HTML."""
    analyzer = JSStaticAnalyzer()
    
    html = """
    <html>
    <head>
        <script src="/static/js/main.js"></script>
        <script src="/static/js/vendor.js"></script>
        <script src="https://cdn.example.com/library.js"></script>
    </head>
    <body>
        <script>console.log('inline');</script>
    </body>
    </html>
    """
    
    script_urls = analyzer.extract_script_urls(html, "https://example.com")
    
    print("Test: Script URL Extraction")
    print(f"  Found {len(script_urls)} script(s)")
    for url in script_urls:
        print(f"  - {url}")
    
    assert len(script_urls) >= 2, "Should extract multiple script URLs"
    assert all(url.startswith("https://example.com") for url in script_urls), "Should resolve to absolute URLs"
    print("  ✓ PASSED\n")


if __name__ == "__main__":
    print("=" * 60)
    print("JavaScript Static Analyzer - Test Suite")
    print("=" * 60)
    print()
    
    try:
        test_secret_detection()
        test_google_api_key_detection()
        test_jwt_detection()
        test_endpoint_discovery()
        test_placeholder_filtering()
        test_script_url_extraction()
        
        print("=" * 60)
        print("ALL TESTS PASSED ✓")
        print("=" * 60)
        
    except AssertionError as e:
        print(f"\n✗ TEST FAILED: {e}")
        exit(1)
    except Exception as e:
        print(f"\n✗ ERROR: {e}")
        import traceback
        traceback.print_exc()
        exit(1)
