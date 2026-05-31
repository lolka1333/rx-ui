-- VLESS Encryption (the application-layer post-quantum / X25519 cipher
-- layer xray-core added on top of TLS). Format reference:
--   `mlkem768x25519plus.<xor_mode>.<seconds>[.<padding>...].<key>`
--
-- Server-side decryption string and client-side encryption string both
-- live in this scheme; the differences are seconds-encoding (server is
-- "600s" or "600-3600s", client is "0rtt" or "1rtt") and which half of
-- the keypair is embedded.
--
-- Columns:
--   mode             — 'none' (default) | 'mlkem768x25519plus'
--   auth             — 'x25519' (32-byte keys) | 'mlkem768' (32-byte
--                       seed + 1184-byte public client key). Post-quantum
--                       protection against "store now, decrypt later".
--   xor_mode         — 'native' (no XOR), 'xorpub', 'random'. Header
--                       obfuscation against DPI.
--   seconds_from/to  — session-token validity window in seconds.
--                       `to` NULL = single value, not a range.
--   padding          — anti-DPI padding string prepended to the key in
--                       the wire format (operator-tunable, default empty).
--   server_key       — base64-url, SECRET. Never shown in UI after the
--                       one-time reveal at generate-time.
--   client_key       — base64-url, public. Embedded in every share-link
--                       for this inbound.
--
-- Keys are generated via `xray vlessenc` subprocess (the bundled binary
-- already speaks both X25519 and ML-KEM-768), so we get bit-for-bit
-- compatibility with xray without dragging a post-quantum crypto crate
-- into the panel.

ALTER TABLE inbounds ADD COLUMN vless_encryption_mode TEXT NOT NULL DEFAULT 'none';
ALTER TABLE inbounds ADD COLUMN vless_encryption_auth TEXT;
ALTER TABLE inbounds ADD COLUMN vless_encryption_xor_mode TEXT;
ALTER TABLE inbounds ADD COLUMN vless_encryption_seconds_from INTEGER;
ALTER TABLE inbounds ADD COLUMN vless_encryption_seconds_to INTEGER;
ALTER TABLE inbounds ADD COLUMN vless_encryption_padding TEXT;
ALTER TABLE inbounds ADD COLUMN vless_encryption_server_key TEXT;
ALTER TABLE inbounds ADD COLUMN vless_encryption_client_key TEXT;
