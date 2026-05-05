"""Gunicorn configuration for DCN Network Tool production deployment."""
import os
import multiprocessing

# Server socket
bind = f"0.0.0.0:{os.environ.get('DCN_PORT', '5757')}"

# Worker processes
# Use 2-4 workers (not too many — each holds SSH connections)
workers = int(os.environ.get("DCN_WORKERS", min(4, multiprocessing.cpu_count() + 1)))
worker_class = "gthread"
threads = int(os.environ.get("DCN_THREADS", "4"))

# Timeouts — SSH commands can take 60-120s
timeout = 180
graceful_timeout = 30
keepalive = 5

# Logging
accesslog = "-"
errorlog = "-"
loglevel = os.environ.get("DCN_LOG_LEVEL", "info")

# Security
limit_request_line = 8190
limit_request_fields = 100

# Preload app for faster worker startup
preload_app = True
