# syntax=docker/dockerfile:1.7

# ---- build stage ------------------------------------------------------------
FROM golang:1.22-alpine AS build

WORKDIR /src

# Cache go module downloads in their own layer.
COPY go.mod ./
# Once we add dependencies and a go.sum exists, uncomment the next line:
# COPY go.sum ./
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

WORKDIR /
COPY --from=build /out/gateway /gateway

USER nonroot:nonroot
EXPOSE 8080

ENTRYPOINT ["/gateway"]
