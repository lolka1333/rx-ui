-- WebSocket transport for VLESS. Adds two nullable columns mirroring the
-- panel's existing xhttp_path/xhttp_host pattern. Path is the URL path on
-- which the WS upgrade is served (Cloudflare-style CDNs typically route by
-- this). Host is the override for the upstream Host header (used when the
-- CDN's incoming SNI differs from what xray sees).
--
-- These columns are unused for non-Ws inbounds — same convention as
-- xhttp_*. The `network` column gains a new accepted value 'ws' on the
-- Rust side; no CHECK constraint is added at the DB level because the
-- existing constraint lives in `InboundNetwork::from_db_str` (we use
-- Rust enums as the source of truth for accepted enum values).

ALTER TABLE inbounds ADD COLUMN ws_path TEXT;
ALTER TABLE inbounds ADD COLUMN ws_host TEXT;
