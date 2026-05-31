-- Optional second TCP port that serves ONLY the public /sub/{token}
-- endpoint (no /api/* admin routes). When non-zero, the panel binds a
-- second axum listener on this port at startup; when zero, only the
-- main panel port serves subscription URLs. Lets the operator put the
-- public subscription endpoint behind a separate firewall rule / CDN
-- without touching the admin port.
ALTER TABLE panel_settings ADD COLUMN sub_port INTEGER NOT NULL DEFAULT 0;
