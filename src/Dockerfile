FROM python:3.12-slim

LABEL description="DCN Network Tool — Network Device Management & AI Analysis"
LABEL version="2.0"

# System deps for paramiko/netmiko (cryptography needs gcc for some wheels)
RUN apt-get update && apt-get install -y --no-install-recommends \
        openssh-client \
        gcc \
        libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# App directory
WORKDIR /app

# Install Python deps first (layer cache)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY app.py app.js index.html gunicorn.conf.py ./

# Copy JMCP directory (auto-generated devices.json goes here at runtime)
COPY jmcp/ ./jmcp/

# Data directories (mounted as volumes in production)
RUN mkdir -p /data/inventory /data/configs/junos /data/configs/eos /data/ssh

# Default env vars (override in docker-compose or k8s)
ENV PYTHONUNBUFFERED=1 \
    DCN_PORT=5757 \
    DCN_SSH_KEY=/data/ssh/netlab_admin \
    DCN_SSH_USER=netadmin \
    DCN_SSH_TIMEOUT=30 \
    DCN_SECURECRT_CSV=/data/inventory/securecrt_sessions.csv \
    DCN_NETBOX_CSV=/data/inventory/netbox_ip_addresses.csv \
    DCN_EOS_CONFIG_DIR=/data/configs/eos \
    DCN_JUNOS_CONFIG_DIR=/data/configs/junos \
    DCN_WORKERS=3 \
    DCN_THREADS=4 \
    DCN_LOG_LEVEL=info \
    # LLM — Docker Model Runner (set LLM_ENABLED=true + MODEL_RUNNER_URL)
    LLM_ENABLED=false \
    LLM_MODEL=ai/qwen3:latest \
    MODEL_RUNNER_URL=http://host.docker.internal:12434 \
    LLM_TIMEOUT=60 \
    # JMCP — Junos MCP Server sidecar (set JMCP_ENABLED=true if running jmcp service)
    JMCP_ENABLED=true \
    JMCP_URL=http://jmcp:30030 \
    # LibreNMS — API tokens (permanent, no cookie needed when inside the network)
    LIBRENMS_EMEA_URL=https://librenms.emea.example.com \
    LIBRENMS_AMER_URL=https://librenms.amer.example.com \
    LIBRENMS_APAC_URL=https://librenms.apac.example.com

EXPOSE 5757

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5757/api/health')"

# Production: gunicorn; Dev: python app.py
CMD ["gunicorn", "-c", "gunicorn.conf.py", "app:app"]
