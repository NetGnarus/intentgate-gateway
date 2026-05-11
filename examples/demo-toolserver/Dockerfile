# syntax=docker/dockerfile:1.7

# Mirrors the extractor's Dockerfile pattern (python:3.11-slim, install via
# pyproject.toml, run as non-root) so operators familiar with one understand
# the other immediately.
FROM python:3.11-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY pyproject.toml README.md ./
COPY app ./app
RUN pip install --upgrade pip && pip install .

# Run as non-root. uid:1001 to avoid colliding with the extractor's uid:1000
# in deployments that schedule both onto the same node.
RUN useradd --system --uid 1001 toolserver && \
    chown -R toolserver:toolserver /app
USER toolserver

LABEL org.opencontainers.image.title="intentgate-demo-toolserver"
LABEL org.opencontainers.image.description="Minimal HTTP-JSON-RPC demo upstream for IntentGate end-to-end demos"
LABEL org.opencontainers.image.source="https://github.com/NetGnarus/intentgate-gateway"
LABEL org.opencontainers.image.licenses="Apache-2.0"
LABEL org.opencontainers.image.vendor="NetGnarus"

EXPOSE 8090

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8090"]
