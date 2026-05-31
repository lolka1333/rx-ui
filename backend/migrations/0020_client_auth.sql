-- Per-client auth secret for Hysteria 2 inbounds.
--
-- VLESS clients identify by the `uuid` column; Hysteria 2 uses a separate
-- string secret transmitted in the HTTP/3 Auth header (mapped to xray's
-- `proxy::hysteria::account::Account.auth`). Storing it in its own column
-- keeps the two schemes clean: a row that ever belonged to a hysteria
-- inbound can carry both fields without one masquerading as the other.
--
-- NULL means "not set" — for hysteria inbounds the protocol layer falls
-- back to the row's `uuid` value, so legacy clients keep working without
-- a manual backfill.

ALTER TABLE clients ADD COLUMN auth TEXT;
