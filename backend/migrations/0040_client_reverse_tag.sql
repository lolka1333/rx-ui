-- VLESS Reverse Proxy tag on a client (xray 26.7.11+). Non-empty makes this
-- client a reverse PORTAL endpoint: when a bridge connects as this user (with
-- the reverse command), xray registers its connection as an outbound under this
-- tag, so routing rules can send user traffic down the tunnel. NULL / empty ≡ a
-- normal client. Set into the VLESS `Account.reverse.tag` proto field.
ALTER TABLE clients ADD COLUMN reverse_tag TEXT;
