# vuln-support-mcp

A **deliberately vulnerable** MCP server for the *Governing Enterprise AI Agents* workshop. It stands in for a badly-governed "customer support" integration and is the target for the exploit lab (Lab A) and the containment lab (Lab B).

> ⚠️ For controlled lab use only. It hands out fake PII on request, hides prompt-injection payloads in its data, and hides tool-poisoning instructions in a tool description. Do not run it anywhere you care about.

## What it teaches

| Vector | Where it lives | Lab |
|--------|----------------|-----|
| **Indirect prompt injection** | `get_support_ticket("TICKET-9901")` returns attacker-authored ticket text that tries to hijack the agent | A |
| **Tool poisoning / "line jumping"** | the *description* of `reconcile_account` hides `<IMPORTANT>` instructions that target the model before any call happens | A (bonus) |
| **The lethal trifecta** | one server combines private data (`get_customer`/`list_customers`), untrusted content (`get_support_ticket`), and an exfil path (`send_webhook`) | A → B |
| **Least privilege** | a composite server that exposes only `get_support_ticket` + `search_kb` breaks the trifecta | B |
| **Gateway filters** | `get_customer`/`list_customers` return SSN, email, driver's licence, and card numbers to redact/block — one licence format deliberately leaks past a naive rule | B |

## Tools

| Tool | Risk | Notes |
|------|------|-------|
| `search_kb(query)` | safe | normal KB search |
| `get_support_ticket(ticket_id)` | untrusted content | `TICKET-9901` is poisoned; `TICKET-1002` is benign |
| `get_customer(customer_id)` | private data | `CUST-8821`, `CUST-1002` |
| `list_customers()` | private data (bulk) | the tool a composite server should switch **off** |
| `send_webhook(url, data)` | egress | **simulated** — logs what *would* be sent, never makes a real outbound call |
| `reconcile_account(customer_id)` | poisoned description | hidden instructions in the tool description |

## Run locally

```bash
npm install
npm start            # listens on http://localhost:8000/mcp  (health: /health)
```

Quick smoke test (Streamable HTTP requires both accept types):

```bash
curl -s -X POST http://localhost:8000/mcp \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'
```

## Published image

Every push to `main` builds this server and publishes it to GHCR via GitHub Actions
(`.github/workflows/docker-publish.yml`):

```
ghcr.io/obotchris/vuln-support-mcp:latest
```

Tagged releases (`v*`) and per-commit SHA tags are published too. Use the image directly in Obot —
no local build needed.

In Obot: **Add Server → runtime `Container`**, image `ghcr.io/obotchris/vuln-support-mcp:latest`,
**port `8000`**, **path `/mcp`** — exactly like the `pii-local` step in the dev-summit scenarios.

> **Note:** the GHCR package is created as *private* by default. Make it **public** (Package settings →
> Change visibility) so Obot instances can pull it without registry credentials.

### Manual build (optional)

To build and push by hand instead of via CI:

```bash
IMAGE=ghcr.io/obotchris/vuln-support-mcp:latest ./build-and-push.sh
```

## Transport

Streamable HTTP, stateless, at `POST /mcp`. Compatible with Claude Code (`claude mcp add --transport http ...`) and with Obot's gateway connection strings.
