# syntax=docker/dockerfile:1

FROM python:3.11-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl git \
 && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md prd.md ./
COPY attack_generator ./attack_generator
COPY schemas ./schemas
COPY examples ./examples
COPY tools ./tools

RUN python -m pip install --upgrade pip && pip install .

RUN adduser --disabled-login --gecos "" appuser \
 && chown -R appuser:appuser /app

RUN mkdir -p /config && chown appuser:appuser /config

USER appuser

EXPOSE 9090

ENV AG_LOG_FORMAT=json

ENTRYPOINT ["attack-generator"]
# --server activates ShowRunner SDK mode (config injection, SIGHUP reload,
# Prometheus metrics on :9090, /healthz endpoint).  Without this flag the
# app runs as a standalone CLI and the SDK is never imported.  The
# orchestrator MUST always pass --server when deploying this container.
CMD ["run", "--server"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD curl -sf http://127.0.0.1:9090/healthz || exit 1
