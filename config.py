"""
Configuration settings for the Autonomous AI Bug Bounty Agent.
"""

import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    """Base configuration class."""
    
    # Google Gemini Configuration
    GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")
    GEMINI_MODEL = "gemini-2.5-flash"
    
    # Scanning Configuration
    MAX_ITERATIONS = int(os.getenv("MAX_ITERATIONS", 15))
    TIMEOUT = int(os.getenv("TIMEOUT", 10))
    
    # Report Configuration
    REPORT_DIR = "reports"
    REPORT_FORMAT = "txt"
    
    # Vulnerability Indicators
    CRITICAL_INDICATORS = [
        r'sql\s+injection',
        r'remote\s+code\s+execution',
        r'rce',
        r'critical',
        r'error in your sql syntax',
        r'syntax error',
        r'warning: mysql',
        r'authentication\s+bypass',
        r'csrf',
        r'xss',
        r'xxe',
        r'ssrf',
        r'path\s+traversal',
        r'command\s+injection',
        r'os\s+command',
        r'confidential',
        r'vulnerability',
        r'security\s+issue',
        r'injection\s+attack',
        r'backdoor',
        r'reverse\s+shell',
    ]
    
    # Common Ports to Test
    COMMON_PORTS = [80, 443, 8080, 8443, 8000, 3000]
    
    # AI Prompting Strategy
    SYSTEM_PROMPT = """You are an expert ethical hacker and bug bounty hunter. 
Your role is to identify vulnerabilities in web applications through systematic testing.
Respond with actionable commands and insights based on reconnaissance data.
Focus on finding critical vulnerabilities like SQLi, RCE, SSRF, XSS, authentication bypass, etc.
Always suggest commands that can be executed in a Linux terminal.
Be thorough but efficient - prioritize critical vulnerability discovery."""
    
    # Scanning Phases
    SCANNING_PHASES = [
        "reconnaissance",
        "enumeration",
        "vulnerability_testing",
        "exploitation",
        "cleanup"
    ]
    
    # Rate Limiting
    REQUEST_DELAY = 0.5  # seconds between requests
    MAX_RETRIES = 3
    
    # Security Settings
    VERIFY_SSL = False  # For testing purposes
    ALLOW_REDIRECTS = True


class DevelopmentConfig(Config):
    """Development configuration."""
    DEBUG = True
    MAX_ITERATIONS = 10
    TIMEOUT = 15


class ProductionConfig(Config):
    """Production configuration."""
    DEBUG = False
    MAX_ITERATIONS = 20
    TIMEOUT = 30


class TestingConfig(Config):
    """Testing configuration."""
    TESTING = True
    MAX_ITERATIONS = 3
    TIMEOUT = 5


def get_config(env: str = None) -> Config:
    """Get configuration based on environment."""
    if env is None:
        env = os.getenv("ENV", "development")
    
    configs = {
        "development": DevelopmentConfig,
        "production": ProductionConfig,
        "testing": TestingConfig,
    }
    
    return configs.get(env, DevelopmentConfig)()
