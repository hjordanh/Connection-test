# Connection Monitor — server/cloud role image.
#
# One image, role chosen by env (this build targets the aggregating server;
# macOS agents run natively, not in a container). SQLite lives on the mounted
# /app/var volume so data survives container restarts.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    # Never pip-install at runtime — the image is immutable; deps are baked in.
    NO_AUTO_INSTALL=1 \
    # Bind all interfaces *inside the container*; the container port is not
    # published publicly — a reverse proxy (Caddy) terminates TLS in front.
    BIND_HOST=0.0.0.0 \
    PORT=8765 \
    DATA_DB=/app/var/connection_monitor.db

WORKDIR /app

# Install deps first so this layer caches across source changes.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Application code.
COPY connection_monitor.py ./
COPY lib/ ./lib/
COPY static/ ./static/
COPY ping_targets.conf ./

# Data dir on a volume; run as an unprivileged user.
RUN mkdir -p /app/var \
    && useradd --system --uid 10001 --home-dir /app monitor \
    && chown -R monitor:monitor /app
USER monitor

VOLUME ["/app/var"]
EXPOSE 8765

# Liveness: the unauthenticated /healthz endpoint.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import os,urllib.request; urllib.request.urlopen('http://127.0.0.1:%s/healthz' % os.environ.get('PORT','8765'), timeout=3)" || exit 1

CMD ["python", "connection_monitor.py"]
