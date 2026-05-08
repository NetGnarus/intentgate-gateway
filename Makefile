.PHONY: build run test vet fmt tidy docker docker-run smoke clean

BIN     := bin/gateway
PKG     := ./...
VERSION ?= 0.1.0-dev
IMAGE   ?= intentgate/gateway:dev

# Default target: produce a local binary at bin/gateway.
build:
	go build -trimpath -ldflags="-X main.version=$(VERSION)" -o $(BIN) ./cmd/gateway

# Build, then run on :8080.
run: build
	./$(BIN)

# Quick fmt / vet / test pass — wire this into CI later.
fmt:
	gofmt -s -w .

vet:
	go vet $(PKG)

test:
	go test -race -count=1 $(PKG)

tidy:
	go mod tidy

# Build the multi-stage container image.
docker:
	docker build --build-arg VERSION=$(VERSION) -t $(IMAGE) .

# Run the image, mapping :8080 to the host.
docker-run:
	docker run --rm -p 8080:8080 $(IMAGE)

# End-to-end smoke test against a running gateway on localhost:8080.
# Requires curl. jq is optional but nice.
smoke:
	@echo '--- GET /healthz'
	@curl -sf http://localhost:8080/healthz | (jq . 2>/dev/null || cat); echo
	@echo '--- POST /v1/tool-call (REST shape)'
	@curl -sX POST http://localhost:8080/v1/tool-call \
		-H 'Content-Type: application/json' \
		-d '{"tool":"read_invoice","args":{"id":"123"},"agent_id":"finance-copilot-v3","session_id":"sess_abc"}' \
		| (jq . 2>/dev/null || cat); echo
	@echo '--- POST /v1/mcp tools/call (JSON-RPC 2.0 shape)'
	@curl -sX POST http://localhost:8080/v1/mcp \
		-H 'Content-Type: application/json' \
		-d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_invoice","arguments":{"id":"123"}}}' \
		| (jq . 2>/dev/null || cat); echo
	@echo '--- POST /v1/mcp ping (expect MethodNotFound)'
	@curl -sX POST http://localhost:8080/v1/mcp \
		-H 'Content-Type: application/json' \
		-d '{"jsonrpc":"2.0","id":2,"method":"ping"}' \
		| (jq . 2>/dev/null || cat); echo

clean:
	rm -rf bin/ out/ dist/
