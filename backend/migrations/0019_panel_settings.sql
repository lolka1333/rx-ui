-- Persisted panel-runtime settings.
--
-- Single-row table (CHECK (id = 1)) holds the values the panel needs
-- before it can even start serving requests: which TCP port to bind
-- and the URL prefix every request must come under. Keeping these in
-- the DB instead of the env file lets the operator change them from
-- the UI without shelling into the host — at the cost of a backend
-- restart to actually apply (axum's router and the TCP listener are
-- bound once at startup).
--
-- `panel_base_path`:
--   * Empty string ≡ panel is reachable at the root.
--   * Non-empty value is stored *with* leading slash, *without*
--     trailing slash (e.g. `/secret-admin`). The boot path normalises
--     stored values into that canonical shape; the API handler also
--     accepts loose input and re-normalises on write.
--
-- Defaults match the current env-var defaults (port 8080, no prefix),
-- so an upgrade to this migration is a no-op for existing deployments
-- until the operator changes something via the new endpoint.

CREATE TABLE panel_settings (
    id              INTEGER PRIMARY KEY CHECK (id = 1),
    panel_port      INTEGER NOT NULL DEFAULT 8080,
    panel_base_path TEXT    NOT NULL DEFAULT '',
    updated_at      TEXT    NOT NULL DEFAULT (datetime('now'))
);

INSERT INTO panel_settings (id) VALUES (1);
