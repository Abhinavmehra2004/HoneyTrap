FROM python:3.12-slim AS base

WORKDIR /app

# Install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY . .

# Create data directories
RUN mkdir -p data/sessions data/uploads

# Expose ports: API/Dashboard, SSH, HTTP honeypot, FTP
EXPOSE 3000 2222 8080 2121

# Run
CMD ["python", "-m", "honeytrap.main"]
