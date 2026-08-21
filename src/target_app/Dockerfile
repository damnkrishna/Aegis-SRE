FROM python:3.10-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    procps \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install
COPY src/target_app/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY src/target_app/ src/target_app/

EXPOSE 8000

ENV PYTHONPATH=/app

CMD ["uvicorn", "src.target_app.main:app", "--host", "0.0.0.0", "--port", "8000"]
