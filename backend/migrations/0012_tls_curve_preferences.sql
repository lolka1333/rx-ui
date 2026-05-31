-- TLS 1.3 elliptic curve preferences (xray `curvePreferences`).
--
-- Ordered list of named curves the server is willing to use for the
-- ECDHE key exchange. First match against the client's `key_share` wins.
--
-- Typical values:
--   X25519           — modern default (Chrome/Firefox/Go/OpenSSL)
--   X25519MLKEM768   — post-quantum hybrid (X25519 + ML-KEM-768)
--   P-256            — NIST secp256r1, legacy compat
--   P-384, P-521     — heavier NIST curves
--
-- Stored as a JSON array of strings (same wire shape as `tls_alpn`).
-- NULL / empty array = let xray pick its compile-time defaults
-- (currently [X25519, X25519MLKEM768, P-256, P-384, P-521]).
--
-- Server-side: this is an "exotic" knob — most operators leave it
-- alone. Surfaced for the two real use-cases: forcing the post-quantum
-- hybrid first, or pinning a FIPS-only curve set.

ALTER TABLE inbounds ADD COLUMN tls_curve_preferences TEXT;
