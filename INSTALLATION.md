# Installation Guide

## System Requirements

### Minimum Requirements
- **OS**: Linux, macOS, or Windows (with WSL)
- **Python**: 3.8 or higher
- **RAM**: 512 MB (minimum), 2 GB (recommended)
- **Disk Space**: 100 MB for installation

### Recommended Requirements
- **Python**: 3.10 or higher
- **RAM**: 4 GB or more
- **Disk Space**: 500 MB (including reports)
- **Network**: Stable internet connection (for API calls)

## Prerequisites

### 1. Python Installation

#### Ubuntu/Debian
```bash
sudo apt-get update
sudo apt-get install python3 python3-pip python3-venv
```

#### macOS
```bash
brew install python@3.11
```

#### Windows
Download from https://www.python.org/downloads/ and run the installer.

### 2. Verify Python Installation
```bash
python3 --version
pip3 --version
```

### 3. Optional: System Tools (for enhanced scanning)

#### Ubuntu/Debian
```bash
sudo apt-get install curl nmap nikto dnsutils whois
```

#### macOS
```bash
brew install curl nmap nikto dnsutils
```

#### Windows (with WSL)
```bash
sudo apt-get install curl nmap nikto dnsutils whois
```

### 4. Google API Key

1. Visit https://aistudio.google.com
2. Sign up or log in to your account
3. Navigate to API keys section
4. Click "Create API key"
5. Copy the key securely
6. Keep the key safe (don't share or commit to version control)

## Installation Steps

### Step 1: Clone or Download Repository

#### Using Git
```bash
git clone <repository-url>
cd bug-bounty-agent
```

#### Using Download
```bash
# Download the ZIP file and extract
unzip bug-bounty-agent.zip
cd bug-bounty-agent
```

### Step 2: Create Virtual Environment

```bash
# Create virtual environment
python3 -m venv venv

# Activate virtual environment
# On Linux/macOS:
source venv/bin/activate

# On Windows:
venv\Scripts\activate
```

### Step 3: Install Dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

**What gets installed:**
- `requests==2.31.0` - HTTP library
- `google-generativeai==0.6.0` - Google Generative AI client
- `python-dotenv==1.0.0` - Environment variable management
- `dnspython==2.4.2` - DNS utilities

### Step 4: Configure Environment

```bash
# Copy the example .env file
cp .env.example .env

# Edit .env file with your API key
nano .env
```

Edit the `.env` file:
```
GOOGLE_API_KEY=your-google-api-key-here
MAX_ITERATIONS=15
TIMEOUT=10
```

### Step 5: Verify Installation

```bash
# Test Python imports
python3 -c "from bug_bounty_agent import BugBountyAgent; print('✓ Installation successful!')"

# Test CLI help
python3 cli.py --help

# Expected output:
# usage: cli.py [-h] [-o OUTPUT] [-i MAX_ITERATIONS] [-t TIMEOUT] [-v] target
# Autonomous AI-powered Bug Bounty Scanner
```

## Verification

### Quick Test

```bash
# Make sure venv is activated
source venv/bin/activate  # or venv\Scripts\activate on Windows

# Run help command
python3 cli.py --help

# You should see:
# usage: cli.py [-h] [-o OUTPUT] [-i MAX_ITERATIONS] [-t TIMEOUT] [-v] target
# 
# Autonomous AI-powered Bug Bounty Scanner
# ...
```

### Full Test

```bash
# Create a test directory
mkdir test_scan
cd test_scan

# Run a test scan (this will fail without valid API key)
python3 ../cli.py https://example.com --max-iterations 1

# You should see scanning output
# (It will fail if GOOGLE_API_KEY is not set, which is expected)
```

## Docker Installation

### Prerequisites
- Docker 20.10+
- Docker Compose 2.0+ (optional)

### Step 1: Build Docker Image

```bash
# Build the image
docker build -t bug-bounty-agent .
```

### Step 2: Run with Docker

```bash
# With .env file
docker run --env-file .env -v "$(pwd)/reports:/app/reports" bug-bounty-agent https://example.com

# Or with explicit API key
docker run -e GOOGLE_API_KEY=your-key -v "$(pwd)/reports:/app/reports" bug-bounty-agent https://example.com
```

### Step 3: Docker Compose (Optional)

```bash
# Start with Docker Compose
docker-compose up

# Stop the service
docker-compose down
```

## Troubleshooting Installation

### Issue: "Python not found"
**Solution:**
```bash
# Check Python is installed
which python3
# or
python --version

# If not installed, see "Python Installation" section above
```

### Issue: "pip: command not found"
**Solution:**
```bash
# Upgrade pip
python3 -m pip install --upgrade pip

# Or install pip if missing
sudo apt-get install python3-pip  # Ubuntu/Debian
```

### Issue: "venv module not found"
**Solution:**
```bash
# Install venv module
sudo apt-get install python3-venv  # Ubuntu/Debian
brew install python@3.11          # macOS
```

### Issue: "Permission denied" when running scripts
**Solution:**
```bash
# Add execute permission
chmod +x bug_bounty_agent.py
chmod +x cli.py

# Or run with python explicitly
python3 cli.py https://example.com
```

### Issue: "ModuleNotFoundError: No module named 'google'"
**Solution:**
```bash
# Ensure virtual environment is activated
source venv/bin/activate  # Linux/macOS
venv\Scripts\activate     # Windows

# Reinstall dependencies
pip install -r requirements.txt
```

### Issue: "GOOGLE_API_KEY not set"
**Solution:**
```bash
# Check .env file exists
ls -la .env

# Check it contains the key
grep GOOGLE_API_KEY .env

# If missing, edit the file
nano .env
# Add: GOOGLE_API_KEY=your-google-api-key-here
```

## Post-Installation Steps

### 1. Create Reports Directory

```bash
mkdir -p reports
```

### 2. Set File Permissions

```bash
chmod +x bug_bounty_agent.py
chmod +x cli.py
chmod +x examples/*.py
```

### 3. Verify Dependencies

```bash
pip list | grep -E "requests|google-generativeai|python-dotenv"
```

### 4. Test with Example

```bash
# Run basic test (will fail with test data, but shows setup works)
python3 examples/basic_usage.py
```

## Environment Setup for Development

### Development Dependencies

```bash
# Install additional development tools (optional)
pip install pytest pytest-cov black flake8 mypy

# Run tests
pytest test_agent.py -v

# Format code
black bug_bounty_agent.py cli.py utils.py config.py

# Lint code
flake8 bug_bounty_agent.py cli.py utils.py config.py

# Type checking
mypy bug_bounty_agent.py cli.py utils.py config.py
```

## Uninstallation

### Remove Virtual Environment

```bash
# Deactivate the environment
deactivate

# Remove the venv directory
rm -rf venv
```

### Remove Application

```bash
# Remove the entire application directory
rm -rf bug-bounty-agent/

# Or if you want to keep code but just clean up
rm -rf venv/
rm -rf reports/
rm .env
```

## Updating Installation

### Update Dependencies

```bash
# Activate virtual environment
source venv/bin/activate

# Upgrade pip
pip install --upgrade pip

# Update all dependencies
pip install --upgrade -r requirements.txt
```

### Update Application Code

```bash
# If using git
git pull origin main

# Reinstall dependencies (in case they changed)
pip install -r requirements.txt
```

## Multiple Versions

### Install Multiple Versions

```bash
# Create separate directories for different versions
mkdir bug-bounty-agent-v1
mkdir bug-bounty-agent-v2

# Clone/setup each version separately
```

### Switch Between Versions

```bash
# Switch to v1
cd bug-bounty-agent-v1
source venv/bin/activate
python3 cli.py https://example.com

# Switch to v2
cd ../bug-bounty-agent-v2
source venv/bin/activate
python3 cli.py https://example.com
```

## Verification Checklist

After installation, verify:

- [ ] Python 3.8+ is installed
- [ ] Virtual environment created and activated
- [ ] Dependencies installed successfully
- [ ] `.env` file created with API key
- [ ] `cli.py --help` works
- [ ] Can import modules: `python3 -c "from bug_bounty_agent import BugBountyAgent"`
- [ ] Reports directory created
- [ ] Example files exist in `examples/`

## Getting Help

If you encounter issues:

1. Check the troubleshooting section above
2. Review error messages carefully
3. Check README.md for more information
4. Verify all prerequisites are installed
5. Ensure API key is valid and set correctly

## Next Steps

After successful installation:

1. Read [QUICKSTART.md](QUICKSTART.md) for quick start
2. Review [README.md](README.md) for full documentation
3. Check [examples/](examples/) directory for usage samples
4. Try running your first scan: `python3 cli.py https://example.com`

---

**Last Updated:** 2024-01-15
**Version:** 1.0
