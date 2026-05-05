# DCN Junos MCP Server — Read-Only Fork
# Based on Juniper/junos-mcp-server (Apache 2.0)
FROM python:3.11-slim

LABEL description="DCN Junos MCP Server (Read-Only)"
LABEL version="1.0"

ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV JMCP_STATELESS=true

# System deps for PyEZ (SSH/NETCONF)
RUN apt-get update && apt-get install -y --no-install-recommends \
        openssh-client \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy read-only server + utils
COPY jmcp_readonly.py .
COPY utils/ ./utils/

# Config and SSH key directories (mounted as volumes)
RUN mkdir -p /app/config /data/ssh

# Non-root user
RUN groupadd -r jmcp && useradd -r -g jmcp -s /bin/bash jmcp
RUN chown -R jmcp:jmcp /app /data
USER jmcp

EXPOSE 30030

HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:30030/mcp/')" || exit 0

# Default: streamable-http on port 30030 (stateless for DCN Tool proxy)
CMD ["python", "jmcp_readonly.py", "-f", "/app/config/devices.json", "-t", "streamable-http", "-H", "0.0.0.0", "-p", "30030"]
