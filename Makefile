.PHONY: build $(BIN) $(IGCTL) run test vet fmt tidy docker docker-run \
        gen-key mint mint-readonly mint-strict \
        smoke smoke-cap smoke-cap-bad smoke-cap-strict \
        igctl clean

BIN     := bin/gateway
IGCTL   := bin/igctl
PKG     := ./...
VERSION ?= 0.1.0-dev
IMAGE   ?= intentgate/gateway:dev

# Default target: produce both binaries.
# $(BIN) and $(IGCTL) are PHONY so 'go build' runs every time and
# decides for itself whether sources actually changed (it's fast and
# idempotent). Without PHONY, make thinks the file existing means the
# target is "done" and silently skips rebuilds — which leaves stale
# binaries lying around after edits.
build: $(BIN) $(IGCTL)

$(BIN):
	go build -trimpath -ldflags="-X main.version=$(VERSION)" -o $(BIN) ./cmd/gateway

$(IGCTL):
	go build -trimpath -o $(IGCTL) ./cmd/igctl

igctl: $(IGCTL)

# Build, then run on :8080.
run: $(BIN)
	./$(BIN)

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

docker-run:
	docker run --rm -p 8080:8080 $(IMAGE)

# ---------------------------------------------------------------------------
# Capability flow helpers
# ---------------------------------------------------------------------------

# Generate and print a fresh master key. Pipe to a file or env var:
#   make gen-key > .master-key
#   export INTENTGATE_MASTER_KEY=$(cat .master-key)
gen-key: $(IGCTL)
	@./$(IGCTL) gen-key

# Mint a token allowing two read-only tools, valid for 1 hour.
# Requires INTENTGATE_MASTER_KEY in the environment.
mint: $(IGCTL)
	@./$(IGCTL) mint \
		--subject finance-copilot-v3 \
		--tools "read_invoice,record_in_ledger" \
		--ttl 1h

# Same but read-only on the public list of read tools, no writes.
mint-readonly: $(IGCTL)
	@./$(IGCTL) mint \
		--subject finance-copilot-v3 \
		--tools "read_invoice" \
		--ttl 1h

# Token with a short TTL — useful for testing expiry handling.
mint-strict: $(IGCTL)
	@./$(IGCTL) mint \
		--subject finance-copilot-v3 \
		--tools "read_invoice" \
		--ttl 10s

# ---------------------------------------------------------------------------
# Smoke tests against a running gateway on :8080
# ---------------------------------------------------------------------------

smoke:
	@echo '--- GET /healthz'
	@curl -sf http://localhost:8080/healthz | (jq . 2>/dev/null || cat); echo
	@echo '--- POST /v1/tool-call (REST shape)'
	@curl -sX POST http://localhost:8080/v1/tool-call \
		-H 'Content-Type: application/json' \
		-d '{"tool":"read_invoice","args":{"id":"123"},"agent_id":"finance-copilot-v3","session_id":"sess_abc"}' \
		| (jq . 2>/dev/null || cat); echo
	@echo '--- POST /v1/mcp tools/call (no token, default dev mode allows)'
	@curl -sX POST http://localhost:8080/v1/mcp \
		-H 'Content-Type: application/json' \
		-d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_invoice","arguments":{"id":"123"}}}' \
		| (jq . 2>/dev/null || cat); echo
	@echo '--- POST /v1/mcp ping (expect MethodNotFound)'
	@curl -sX POST http://localhost:8080/v1/mcp \
		-H 'Content-Type: application/json' \
		-d '{"jsonrpc":"2.0","id":2,"method":"ping"}' \
		| (jq . 2>/dev/null || cat); echo

# Smoke test with a valid capability token.
# Usage:  make smoke-cap TOKEN=<encoded-token>
smoke-cap:
	@test -n "$(TOKEN)" || (echo "set TOKEN=<encoded-token> (run 'make mint' first)"; exit 1)
	@echo '--- POST /v1/mcp tools/call (read_invoice, should ALLOW)'
	@curl -sX POST http://localhost:8080/v1/mcp \
		-H 'Content-Type: application/json' \
		-H 'Authorization: Bearer $(TOKEN)' \
		-d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_invoice","arguments":{"id":"123"}}}' \
		| (jq . 2>/dev/null || cat); echo
	@echo '--- POST /v1/mcp tools/call (send_email, should BLOCK on whitelist)'
	@curl -sX POST http://localhost:8080/v1/mcp \
		-H 'Content-Type: application/json' \
		-H 'Authorization: Bearer $(TOKEN)' \
		-d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"send_email","arguments":{}}}' \
		| (jq . 2>/dev/null || cat); echo

# Smoke test with a tampered token (alter the last character of the
# signature). Should reject with capability_failed.
smoke-cap-bad:
	@test -n "$(TOKEN)" || (echo "set TOKEN=<encoded-token>"; exit 1)
	@echo '--- POST /v1/mcp tools/call (tampered token, should BLOCK)'
	@curl -sX POST http://localhost:8080/v1/mcp \
		-H 'Content-Type: application/json' \
		-H 'Authorization: Bearer $(TOKEN)X' \
		-d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_invoice","arguments":{}}}' \
		| (jq . 2>/dev/null || cat); echo

# Smoke test with the gateway in strict mode (INTENTGATE_REQUIRE_CAPABILITY=true).
# Sending a request with no Authorization header should be rejected.
smoke-cap-strict:
	@echo '--- POST /v1/mcp tools/call (no token, strict mode, should BLOCK)'
	@curl -sX POST http://localhost:8080/v1/mcp \
		-H 'Content-Type: application/json' \
		-d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_invoice","arguments":{}}}' \
		| (jq . 2>/dev/null || cat); echo

clean:
	rm -rf bin/ out/ dist/
