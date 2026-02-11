# Multi-stage build for VulnScan
FROM python:3.11-slim AS builder

# Install nmap
RUN apt-get update && \
    apt-get install -y --no-install-recommends nmap && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY . .
RUN pip install --no-cache-dir -e .

ENTRYPOINT ["python", "-m", "scanner.cli"]
CMD ["--help"]
