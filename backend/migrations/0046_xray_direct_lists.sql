-- Direct lists: traffic that must NOT go through the proxy chain.
--
-- The panel already had the blocking half (`xray_blocked_ips` /
-- `xray_blocked_domains` → the blackhole outbound, migration 0032). Its mirror
-- image was missing: matchers routed to the `direct` outbound, so an operator
-- could keep local networks, a home country, or a bank's domains off the tunnel
-- without writing a full custom rule for each.
--
-- Same shape as the blocked pair — a JSON array of xray matchers
-- (`geoip:private`, `geosite:category-ads-all`, `ext:geoip_RU.dat:ru`, a bare
-- CIDR or domain) — so the existing validators, the emitters and the geo
-- multi-select in the UI all apply unchanged.
--
-- Empty by default: adding a direct route to an existing install would change
-- where its traffic goes, and that is the operator's call, never an upgrade's.
ALTER TABLE panel_settings ADD COLUMN xray_direct_ips TEXT NOT NULL DEFAULT '[]';
ALTER TABLE panel_settings ADD COLUMN xray_direct_domains TEXT NOT NULL DEFAULT '[]';
