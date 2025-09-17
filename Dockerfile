# syntax=docker/dockerfile:1

FROM python:3.11-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# OS deps (certs for TLS; curl only for optional local smoke checks)
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*

# Copy project files (adjust paths if your repo layout differs)
COPY pyproject.toml README.md prd.md ./
COPY attack_generator ./attack_generator
COPY schemas ./schemas
COPY examples ./examples
COPY tools ./tools

# Install the package (this will also pull the PyPI "container-control" dep)
RUN python -m pip install --upgrade pip \
 && pip install .

# Run as non-root
RUN adduser --disabled-login --gecos "" appuser \
 && chown -R appuser:appuser /app
USER appuser

# App listens on 8080; ShowRunner will map to its external port (e.g. 5005)
EXPOSE 8080

# Defaults for server mode on a single port
ENV AG_LOG_FORMAT=json \
    AG_METRICS_PORT=8080

ENTRYPOINT ["attack-generator"]
CMD ["run","--server"]

# Simple health check against the control API
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD python -c "import os,urllib.request,sys; \
u=f'http://127.0.0.1:{os.environ.get(\"AG_METRICS_PORT\",\"8080\")}/api/health'; \
sys.exit(0 if urllib.request.urlopen(u,timeout=3).getcode()==200 else 1)"
