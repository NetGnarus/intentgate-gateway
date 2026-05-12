# syntax=docker/dockerfile:1.7

# ---- build stage ------------------------------------------------------------
# Pinned to match the toolchain in go.mod. Bump both together.
FROM golang:1.26-alpine AS build

WORKDIR /src

# Cache go module downloads in their own layer.
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the source.
COPY . .

# Static binary, stripped, with paths trimmed for reproducibility.
ENV CGO_ENABLED=0 GOOS=linux
ARG VERSION=dev
RUN go build \
      -trimpath \
      -ldflags="-s -w -X main.version=${VERSION}" \
      -o /out/gateway \
      ./cmd/gateway

# ---- runtime stage ----------------------------------------------------------
# Distroless static is ~2 MB, contains no shell and runs as nonroot by default.
FROM gcr.io/distroless/static:nonroot

# OCI labels — surfaced on the GHCR package page and by `docker inspect`.
# Keep these in sync with the repo metadata.
LABEL org.opencontainers.image.title="intentgate-gateway"
LABEL org.opencontainers.image.description="Self-hosted authorization gateway for AI agents (capability + intent + policy + budget)"
LABEL org.opencontainers.image.source="https://github.com/NetGnarus/intentgate-gateway"
LABEL org.opencontainers.image.url="https://github.com/NetGnarus/intentgate-gateway"
LABEL org.opencontainers.image.documentation="https://github.com/NetGnarus/intentgate-gateway#readme"
LABEL org.opencontainers.image.licenses="Apache-2.0"
LABEL org.opencontainers.image.vendor="NetGnarus"

WORKDIR /
COPY --from=build /out/gateway /gateway

USER nonroot:nonroot
EXPOSE 8080

ENTRYPOINT ["/gateway"]
