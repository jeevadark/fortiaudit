FROM python:3.11-slim

LABEL maintainer="your.email@example.com"
LABEL description="FortiAudit - Fortinet Firewall Security Audit Tool"

RUN apt-get update && apt-get install -y \
    nmap \
    snmp \
    hping3 \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -u 1000 fortiaudit

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN pip install -e .

RUN mkdir -p /app/reports /app/configs /app/logs && \
    chown -R fortiaudit:fortiaudit /app

USER fortiaudit

ENV PYTHONUNBUFFERED=1

ENTRYPOINT ["python", "-m", "fortiaudit.cli"]
CMD ["--help"]
