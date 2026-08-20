-- WireGuard peers: one keypair and one tunnel address per client.
--
-- The address is what identifies the peer at runtime — xray's WireGuard
-- inbound looks a user up by the source address inside the tunnel
-- (`GetUserByAddr` in proxy/wireguard/server.go), not by the key — so it has
-- to be unique within an inbound and is assigned from the inbound's subnet.
--
-- The private key is held here because the panel hands the client a ready
-- config: WireGuard has no shared secret like a VLESS UUID, so a config the
-- operator can copy or scan can only exist if the panel generated both halves.
-- Every column is NULL for a client of any other protocol.
ALTER TABLE clients ADD COLUMN wg_private_key TEXT;
ALTER TABLE clients ADD COLUMN wg_public_key TEXT;
ALTER TABLE clients ADD COLUMN wg_address TEXT;
