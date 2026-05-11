"""IntentGate demo tool server.

A minimal HTTP-JSON-RPC service the gateway can forward to as
INTENTGATE_UPSTREAM_URL, so /v1/mcp returns real tool results
instead of the gateway's "stub: no upstream configured" placeholder.

The whole point: every demo / verify-session-N.sh in the IntentGate
project ended at "the gateway authorized this call, trust me bro."
With this upstream wired in, the demos now show authorization +
actual tool results, end-to-end.

Three mock tools, picked because they map cleanly to the existing
pitch scenarios:

  - read_invoice(id)         — basic read, used in most verify scripts
  - list_customers(limit)    — bulk read, useful for data-exfiltration policy demos
  - transfer_funds(...)      — high-risk write, the standard "escalate when
                               amount_eur > 5000" demo target

Tools return synthetic data, no DB connection required. The point
is to give the gateway something to forward to so the response body
is non-stub; the data itself is fixture.

# Protocol

JSON-RPC 2.0 over HTTP POST /. The gateway forwards the entire
JSON-RPC envelope from its /v1/mcp endpoint. We implement two
methods:

  - tools/list  : returns the static catalog
  - tools/call  : dispatches to the named tool

Unknown methods or unknown tool names return JSON-RPC errors with
the standard codes. Tool exceptions become CodeInternalError.

This file is deliberately self-contained (no separate handler
module, no database client, no auth) — the whole point is that the
demo upstream is a small understandable artifact someone can read
in one sitting. Production tool servers are a different shape.
"""

from __future__ import annotations

import os
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI(
    title="IntentGate demo tool server",
    description=(
        "Minimal HTTP-JSON-RPC tool server for demoing the IntentGate "
        "gateway end-to-end. Not for production use."
    ),
)

# ---------------------------------------------------------------------------
# Tool catalog
# ---------------------------------------------------------------------------

TOOLS: list[dict[str, Any]] = [
    {
        "name": "read_invoice",
        "description": "Read a single invoice by id.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "id": {"type": "string", "description": "Invoice id."},
            },
            "required": ["id"],
        },
    },
    {
        "name": "list_customers",
        "description": "List customer records, capped by limit.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "limit": {
                    "type": "integer",
                    "description": "Max records to return (1..100).",
                    "default": 10,
                },
            },
            "required": [],
        },
    },
    {
        "name": "transfer_funds",
        "description": (
            "Move money from one account to another. The demo policy "
            "in the pitch kit escalates this above 5,000 EUR."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "from_account": {"type": "string"},
                "to_account": {"type": "string"},
                "amount_eur": {
                    "type": "number",
                    "description": "Amount in EUR.",
                },
            },
            "required": ["from_account", "to_account", "amount_eur"],
        },
    },
]


# Fixture data. read_invoice falls back to a synthetic invoice when
# the requested id isn't in this map, so the demo never 404s — the
# point is to demonstrate the gateway's authorization path, not to
# stress-test fixture lookups.
INVOICE_FIXTURES: dict[str, dict[str, Any]] = {
    "INV-1001": {
        "id": "INV-1001",
        "vendor": "Acme Office Supplies",
        "amount_eur": 1240.50,
        "due_date": "2026-05-30",
        "status": "open",
    },
    "INV-1002": {
        "id": "INV-1002",
        "vendor": "Globex Cloud Hosting",
        "amount_eur": 8900.00,
        "due_date": "2026-06-15",
        "status": "open",
    },
}

CUSTOMER_FIXTURES: list[dict[str, Any]] = [
    {"id": "CUST-1", "name": "Initech BV", "country": "NL", "tier": "enterprise"},
    {"id": "CUST-2", "name": "Hooli SARL", "country": "FR", "tier": "mid-market"},
    {"id": "CUST-3", "name": "Pied Piper Inc.", "country": "US", "tier": "startup"},
    {"id": "CUST-4", "name": "Massive Dynamic", "country": "GB", "tier": "enterprise"},
]


# ---------------------------------------------------------------------------
# Tool implementations
# ---------------------------------------------------------------------------


def tool_read_invoice(args: dict[str, Any]) -> dict[str, Any]:
    """Return the invoice by id, falling back to a synthetic record
    so the demo doesn't 404 on unfamiliar ids."""
    invoice_id = str(args.get("id", "")).strip()
    if not invoice_id:
        raise ValueError("id is required")
    if invoice_id in INVOICE_FIXTURES:
        return INVOICE_FIXTURES[invoice_id]
    # Synthetic fallback so live demos with arbitrary ids still work.
    return {
        "id": invoice_id,
        "vendor": "Synthetic Vendor Corp.",
        "amount_eur": 999.00,
        "due_date": "2026-06-30",
        "status": "open",
        "_note": "synthetic record (id not in fixture map)",
    }


def tool_list_customers(args: dict[str, Any]) -> dict[str, Any]:
    """Return a slice of the customer fixture list. Clamps limit to
    [1, 100]; the upper bound keeps demo responses from getting huge."""
    raw = args.get("limit", 10)
    try:
        limit = int(raw)
    except (TypeError, ValueError):
        limit = 10
    limit = max(1, min(limit, 100))
    return {"customers": CUSTOMER_FIXTURES[:limit], "total": len(CUSTOMER_FIXTURES)}


def tool_transfer_funds(args: dict[str, Any]) -> dict[str, Any]:
    """Return a 'would-transfer' acknowledgement. The DEMO doesn't
    move real money — this is a deliberately stubbed return so the
    pitch can show the gateway's policy + escalation behavior without
    needing a real banking integration. Production tool servers
    obviously would do the actual transfer here."""
    src = str(args.get("from_account", "")).strip()
    dst = str(args.get("to_account", "")).strip()
    try:
        amount = float(args.get("amount_eur", 0))
    except (TypeError, ValueError):
        amount = 0.0
    if not src or not dst:
        raise ValueError("from_account and to_account are required")
    if amount <= 0:
        raise ValueError("amount_eur must be > 0")
    return {
        "ok": True,
        "from_account": src,
        "to_account": dst,
        "amount_eur": amount,
        "reference": f"DEMO-TX-{abs(hash((src, dst, amount))) % 100000:05d}",
        "_note": "demo tool — no real banking integration",
    }


TOOL_DISPATCH = {
    "read_invoice": tool_read_invoice,
    "list_customers": tool_list_customers,
    "transfer_funds": tool_transfer_funds,
}


# ---------------------------------------------------------------------------
# JSON-RPC handler
# ---------------------------------------------------------------------------

# JSON-RPC 2.0 error codes the gateway expects.
PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603


def _error(req_id: Any, code: int, message: str, data: Any = None) -> dict[str, Any]:
    """Build a JSON-RPC error response."""
    err: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        err["data"] = data
    return {"jsonrpc": "2.0", "id": req_id, "error": err}


def _result(req_id: Any, result: Any) -> dict[str, Any]:
    """Build a JSON-RPC success response. The MCP convention wraps
    tool results in {content: [...], isError: false}, which the
    gateway forwards verbatim. We match that shape so the gateway
    doesn't have to special-case our responses."""
    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "result": {
            "content": [
                {"type": "text", "text": _stringify(result)},
            ],
            "isError": False,
            "_data": result,  # convenience: clients that prefer structured data can use this
        },
    }


def _stringify(value: Any) -> str:
    """Render a tool result into the human-readable text content
    field. For the demo we just dump the structured result; a real
    tool server might pretty-print or summarize."""
    import json

    try:
        return json.dumps(value, indent=2, ensure_ascii=False, sort_keys=True)
    except TypeError:
        return str(value)


@app.post("/")
async def jsonrpc(request: Request) -> JSONResponse:
    """JSON-RPC 2.0 endpoint. Dispatches on method:

      - tools/list : returns the static catalog
      - tools/call : invokes the named tool

    Unknown methods return METHOD_NOT_FOUND. Tool exceptions are
    surfaced as INTERNAL_ERROR with the exception's message in the
    error.data field so the gateway can surface it cleanly."""
    try:
        body = await request.json()
    except Exception as exc:
        return JSONResponse(
            content=_error(None, PARSE_ERROR, "parse error", str(exc)),
            status_code=400,
        )

    req_id = body.get("id")
    method = body.get("method", "")
    params = body.get("params") or {}

    if body.get("jsonrpc") != "2.0":
        return JSONResponse(
            content=_error(req_id, INVALID_REQUEST, "jsonrpc must be '2.0'"),
            status_code=400,
        )

    if method == "tools/list":
        return JSONResponse(content=_result(req_id, {"tools": TOOLS}))

    if method == "tools/call":
        name = params.get("name", "")
        args = params.get("arguments") or {}
        fn = TOOL_DISPATCH.get(name)
        if fn is None:
            return JSONResponse(
                content=_error(req_id, METHOD_NOT_FOUND, f"unknown tool: {name}"),
            )
        try:
            return JSONResponse(content=_result(req_id, fn(args)))
        except ValueError as exc:
            return JSONResponse(
                content=_error(req_id, INVALID_PARAMS, str(exc)),
            )
        except Exception as exc:  # noqa: BLE001 — last-resort wrap
            return JSONResponse(
                content=_error(req_id, INTERNAL_ERROR, "tool error", str(exc)),
            )

    return JSONResponse(content=_error(req_id, METHOD_NOT_FOUND, f"unknown method: {method}"))


@app.get("/healthz")
async def healthz() -> dict[str, Any]:
    """Match the gateway's healthz shape so the helm chart's
    liveness/readiness probes work the same way."""
    return {"status": "ok", "version": os.getenv("DEMO_TOOLSERVER_VERSION", "0.1.0")}
