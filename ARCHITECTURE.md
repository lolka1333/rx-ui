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
- No outbound/routing UI yet (only inbounds + clients).
- No ACME / auto-certs. Operator pastes PEM strings manually.
- No password change UI (yet — planned).

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

### Inbounds table — wide-column

Every xray knob = one DB column (e.g. `xhttp_xmux_max_concurrency`,
`tls_reject_unknown_sni`). Current count: **~70 columns**.

**Why:** simple SQL, type-checked at compile time via sqlx macros,
trivial to query per field (`WHERE port = ?` for uniqueness checks).

**Cost:** adding one field is a ~9-14-file edit — see below.

### Clients table — narrow

Per-inbound users. Just `id`, `inbound_id`, `email`, `uuid`,
`flow`, `enabled`, `note`. Flow `None` = inherit from inbound's
`vless_flow`.

## Adding an inbound field

The current state of the world. **This is the dominant maintenance
cost of the project and is on the refactor list.**

For a new column `foo_bar`:

1. `backend/migrations/NNNN_add_foo_bar.sql` — `ALTER TABLE inbounds ADD COLUMN foo_bar TYPE;`
2. `backend/src/models/inbound.rs` — add `pub foo_bar: ...` to three structs: `Inbound`, `InboundCreate`, `InboundUpdate`.
3. `backend/src/api/inbounds.rs`:
   - add `foo_bar: ...` to the `Row` struct
   - extend `row_to_inbound` to copy/decode it
   - add `foo_bar` to **all 4 SELECT statements** (`list`, `get_one`, `read_row`, plus the related path)
   - extend the INSERT in `create`: column list + `?` placeholder + bind parameter
   - add a new `if let Some(...) = body.foo_bar { sqlx::query!("UPDATE ...") }` block in `update`
   - add comparison to `needs_resync`
4. `backend/src/main.rs` — extend the reconciler's SELECT and the struct mapping it feeds.
5. `backend/src/xray/inbound_proto.rs` — feed `inb.foo_bar` into the proto.
6. `backend/src/xray/share_link.rs` — if relevant for client URI.
7. Regenerate caches:
   ```bash
   cargo sqlx prepare -- --bin rx-ui
   cargo test export_bindings   # regenerates ts-rs TS files
   ```
8. `frontend/src/pages/Inbounds.tsx`:
   - `FormValues` interface
   - `DEFAULTS` object
   - `initialValues` hydration in `InboundForm`
   - `build-payload` in the save mutation
   - the actual `<Form.Item name="foo_bar">` rendering somewhere
9. `frontend/src/i18n/ru.ts` + `en.ts` — label + optional tooltip key.

**Why this hurts:** silent drift between the four parallel listings
in step 8 has bitten us multiple times (`xhttp_headers` was missing
from `DEFAULTS` once, save crashed with "not iterable" on submit).

**Planned mitigation:** collapse all the optional config fields into
a single `config_json TEXT` column carrying a serde-typed
`InboundConfig` struct. Keeps `id` / `tag` / `port` / `enabled` as
real columns for indexing; everything else lives in the blob. Brings
the edit cost down to ~3 files per new field.

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

In rough priority order — the corresponding refactor proposals
live in the project-level audit notes:

1. **Wide-column inbound schema** (described above) — 70+ columns
   driving 9-14 file touches per new field. The `config_json`
   blob refactor would cut this to ~3.
2. **`Inbounds.tsx` ~2200 LoC** — kitchen-sink file holding the
   page, form, 5 tab components, advanced collapses, client
   sub-panel, share-link modal, helpers, defaults, payload
   builder. Should split into `pages/Inbounds/{index, InboundForm,
   tabs/*, ClientsPanel, ShareLinkModal, formSchema}.tsx`.
3. **`api/inbounds.rs` ~1100 LoC** with 35 cookie-cutter UPDATE
   blocks and 4 duplicate 19-line SELECT lists. Becomes obsolete
   if #1 ships (one column = one bind instead of 60+).
4. **No frontend tests** — vitest + react-testing-library on the
   form payload builder, the URL parser, and i18n key coverage.

Each of these is a ~half-day to 2-day refactor; do them in the
order above to avoid touching the same code twice.
