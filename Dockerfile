# Aegis-SRE Production Multi-Stage Container Blueprint
FROM python:3.10-slim

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source code, knowledge base, and tests
COPY src/ ./src/
COPY test/ ./test/
COPY PHASES.md README.md ./

# Create logs directory
RUN mkdir -p logs

# Expose FastAPI REST API + WebSockets port
EXPOSE 8000

# Default container startup command
CMD ["python", "-m", "src.dashboard.server"]
