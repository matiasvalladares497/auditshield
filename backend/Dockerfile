FROM python:3.11-slim

# Dependencias del sistema necesarias
RUN apt-get update && apt-get install -y \
    nmap \
    curl \
    dnsutils \
    whois \
    openssl \
    libffi-dev \
    libssl-dev \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

COPY . .

RUN chmod +x start.sh

EXPOSE 8000

CMD ["./start.sh"]
