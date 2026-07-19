# Architecture

Bird's-eye view of how rx-ui works. For day-to-day operator usage see
[README.md](README.md).

## Goals & non-goals

**Goals:**
- Single-admin panel for **one** xray-core instance on the same host.
- Manage VLESS inbounds + their per-inbound clients without restarting
  xray (every change pushes via gRPC `HandlerService`).
- Self-contained: panel binary + xray binary + SQLite file = everything
  needed; backup = copy three files.
- Operator-friendly: every form field has a tooltip explaining its
  xray-side effect, defaults match xray defaults.

**Non-goals (intentional limits):**
- No multi-user / RBAC. Single admin.
- No multi-node / cluster mode. One panel, one xray.
- No ACME / auto-certs. Operator pastes PEM strings manually.

## Processes

```
┌─────────────────────────────────────────────────────────────────┐
│ Host machine                                                    │
│                                                                 │
│  ┌──────────────────┐    spawn / attach  ┌─────────────────┐    │
│  │ rx-ui   │ ─────────────────► │ xray.exe        │    │
│  │ (Rust, axum)     │                    │ (xray-core bin) │    │
│  │ :8080 HTTP API   │ ◄── gRPC :62789 ── │ HandlerService  │    │
│  └──────────────────┘                    └─────────────────┘    │
│         ▲                                       ▲               │
│         │ HTTP                                  │ TCP/WS/XHTTP  │
│         │ + JWT                                 │ + Reality/TLS │
│         │                                       │               │
│  ┌──────────────────┐                    ┌─────────────────┐    │
│  │ Browser (panel)  │                    │ End user        │    │
│  │ Vite-served SPA  │                    │ (v2rayN, ...)   │    │
│  └──────────────────┘                    └─────────────────┘    │
└─────────────────────────────────────────────────────────────────┘
```

**rx-ui** spawns xray with a minimal bootstrap config that
exposes the `HandlerService` on `127.0.0.1:62789` (an internal
`dokodemo-door` inbound). All operator-driven inbound changes go
through this gRPC channel — xray's config-file is NEVER reloaded
after boot.

If xray was already running with the panel's known config-file path,
the backend **attaches** to that PID instead of spawning. Lets the
operator stop/start the panel without killing live tunnels.

## Request flow

A typical "operator creates a new inbound" flow:

1. Browser → `POST /api/inbounds` with the full body
2. axum handler in `backend/src/api/inbounds.rs::create`:
   - validate (`validate_flow_network`, `ensure_port_free`)
   - generate Reality keypair if `security=reality`
   - INSERT into `inbounds` table
   - build `InboundHandlerConfig` proto via
     `xray::inbound_proto::inbound_to_handler_config`
   - send `AddInbound` gRPC call to xray
   - on failure: log + return 500 (DB row stays — reconciliation on
     next boot retries the push)
3. Response: full `Inbound` JSON back to the browser

Client mutations (`POST /api/inbounds/{id}/clients`) use
`AlterInbound` with `AddUserOperation` / `RemoveUserOperation` —
the inbound itself doesn't reload, just the user list.

## Reconciliation on startup

On every panel boot (`backend/src/main.rs`):
1. Apply pending migrations (`sqlx::migrate!()`).
2. Read every `enabled=true` inbound from the DB.
3. For each: send `RemoveInbound` (idempotent — ignore "not found")
   then `AddInbound`. This **drops connections briefly** but
   guarantees xray's runtime state matches the panel's view of truth.

The remove-then-add cycle is what lets you tweak the DB directly
(or restore from backup), restart the panel, and trust the result.

## Schema choices

### Inbounds table — typed JSON layers

Five JSON blob columns carry the xray knobs: `protocol_config`,
`transport_config`, `security_config`, `sniffing_config`,
`finalmask_config` (plus `sockopt_config`). Only what the panel queries
stays a real column: `id`, `tag`, `enabled`, `listen`, `port`, timestamps.

**Why:** each blob deserialises into a tagged enum (`ProtocolConfig`,
`TransportConfig`, …) whose variants live in `protocols/`, `transports/`
and `security/`. Adding a knob is a change to one Rust enum plus the form
that edits it — not an ALTER TABLE and a sweep through every SELECT.

**Cost:** the blobs are opaque to SQL, so anything that needs to filter on
a knob has to load and decode rows. Nothing does today; `port` uniqueness
and tag lookups run against the real columns.

This replaced a wide-column layout of ~70 columns; migrations 0014-0016
moved the data into the blobs and dropped the old columns.

### Clients table — narrow

Per-inbound users: `id`, `inbound_id`, `email`, `uuid`, `auth`, `flow`,
`reverse_tag`, `enabled`, `note`, plus quota/expiry and subscription
fields. Flow `None` = inherit from the inbound's VLESS flow.

## Adding an inbound field

For a knob on an existing layer (say a new VLESS option):

1. `backend/src/protocols/vless/proto.rs` — add the field to the struct.
2. `backend/src/xray/orchestrator.rs` — feed it into the proto the
   layer emits.
3. `backend/src/xray/share_link.rs` — if it belongs in the client URI.
4. `cargo test` — regenerates the ts-rs TypeScript bindings.
5. `frontend/src/pages/Inbounds/` — the tab that owns that layer, plus
   `form/adapters.ts` if the form shape differs from the wire shape.
6. `frontend/src/i18n/en.ts` + `ru.ts` — label and optional tooltip.

No migration, no SELECT edits: the blob column already carries whatever
the enum serialises. A new LAYER (a new transport, say) additionally
needs its module under `transports/` and a registry entry.

## Frontend ↔ backend type sharing

`backend/src/models/*.rs` is the source of truth for every data
shape that crosses the API. ts-rs (`#[derive(TS)]` +
`#[ts(export, export_to = "../../frontend/src/api/types/")]`)
generates the TS counterparts:

```rust
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../frontend/src/api/types/")]
pub struct Inbound { ... }
```

Generated files (`frontend/src/api/types/Inbound.ts` etc.) are
**committed to source**. Regenerated by `cargo test
export_bindings` whenever a struct changes; CI verifies they're in
sync (or will, once we add it to the workflow).

The handful of types deliberately NOT re-exported from
`frontend/src/api/types/index.ts` (`ClientUpdate`, `LoginRequest`,
`LoginResponse`) are inline-typed at the call sites — re-exporting
just pollutes IDE autocomplete.

## Layered validation

Three places where a bad value gets rejected, in order of preference:

1. **Frontend Antd `rules`** — instant feedback, no round-trip.
   Used for required-field checks (tag, port, reality_dest).
2. **Backend up-front validation** in `api/inbounds.rs` — runs
   before any DB write. Catches cross-field combos
   (`validate_flow_network`) and uniqueness
   (`ensure_port_free`). Returns 4xx with operator-friendly text.
3. **xray gRPC `AddInbound` response** — last line of defense.
   The backend treats a gRPC error as 500 ("saved but not applied
   to xray") so the operator knows to fix-and-retry.

The `validate_flow_network` function in particular encodes business
rules sourced from `Xray-core/infra/conf/transport_internet.go`:
Vision flow is TCP-only, Reality security is RAW/XHTTP/gRPC-only
(no WebSocket). These are exercised by unit tests
(`#[cfg(test)] mod validate_flow_network_tests`) so a future xray
upgrade that loosens or tightens the rules is caught immediately.

## Testing strategy

Three layers:

- **Pure-function unit tests** (Rust `#[cfg(test)]`) — covers
  `parse_range`, `validate_flow_network`, `share_link::build_*`,
  `keygen` round-trips, enum `as_db_str`/`from_db_str` symmetry.
  Fast (<1s), no DB, run on every `cargo test`.
- **ts-rs export tests** — `#[test]` functions ts-rs generates
  that re-emit the TS files. Failing one means the on-disk
  bindings drifted from the Rust models.
- **End-to-end smoke** — manual right now: spawn xray-as-client,
  curl through it via http-proxy, hit `api.ipify.org`. Documented
  per-transport in commit messages. Could become a CI job but
  requires a Docker-orchestrated xray + panel + xray-client trio.

## Known structural weaknesses (planned cleanup)

- **No frontend tests** — vitest + react-testing-library on the
  form payload builder, the URL parser, and i18n key coverage.

