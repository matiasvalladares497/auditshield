FROM python:3.11-slim

# Install system dependencies including nmap, openssl, dnsutils, cairo
RUN apt-get update && apt-get install -y \
    nmap \
    curl \
    dnsutils \
    whois \
    openssl \
    libffi-dev \
    libssl-dev \
    gcc \
    libcairo2 \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libgdk-pixbuf2.0-0 \
    shared-mime-info \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000

CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
