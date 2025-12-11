FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    nmap \
    dnsutils \
    whois \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY requirements.txt .

# Install Python dependencies and Playwright browsers
RUN pip install --no-cache-dir -r requirements.txt \
    && playwright install --with-deps chromium

# Copy application code
COPY . .

# Create reports directory
RUN mkdir -p reports

# Set environment variables
ENV PYTHONUNBUFFERED=1

# Run the CLI
ENTRYPOINT ["python", "cli.py"]
CMD ["--help"]
