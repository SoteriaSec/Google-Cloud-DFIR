# Base image
FROM python:3.11-slim

# Avoid .pyc files and ensure unbuffered output
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Install any system dependencies you might want (keep minimal)
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Working directory for the app code
WORKDIR /app

# Install Python dependencies first (better layer caching)
COPY ../requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the app (including gcp_log_collector.py)
COPY ../gcp_log_collector.py /app

# Directory for configuration (client_secret.json + token.json)
RUN mkdir -p /config

# Directory for outputs if you want to map logs out separately
RUN mkdir -p /data

# IMPORTANT: tell the script where to find credentials by default
# (without needing to pass env vars on every docker run)
ENV GCP_OAUTH_CLIENT_SECRETS=/config/client_secret.json \
    GCP_OAUTH_TOKEN_FILE=/config/token.json

# Default entrypoint is the Python script; subcommands and options follow
ENTRYPOINT ["python", "gcp_log_collector.py"]
CMD ["--help"]
