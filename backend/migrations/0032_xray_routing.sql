-- xray routing rules (the "basic connections" block). Like the strategy
-- columns in 0031, these live in the bootstrap config, so they apply on an
-- xray restart. The three list columns hold JSON arrays of strings (domains,
-- IPs/CIDRs, or geoip:/geosite:/ext: matchers).
--
--   * xray_block_bittorrent — route the sniffed `bittorrent` protocol to a
--     blackhole outbound (needs inbound sniffing on to detect it).
--   * xray_blocked_ips / xray_blocked_domains — blackhole traffic to these.
--   * xray_ipv4_domains — force these domains out over IPv4 (routed to a
--     freedom outbound with domainStrategy UseIPv4).
ALTER TABLE panel_settings ADD COLUMN xray_block_bittorrent INTEGER NOT NULL DEFAULT 0;
ALTER TABLE panel_settings ADD COLUMN xray_blocked_ips TEXT NOT NULL DEFAULT '[]';
ALTER TABLE panel_settings ADD COLUMN xray_blocked_domains TEXT NOT NULL DEFAULT '[]';
ALTER TABLE panel_settings ADD COLUMN xray_ipv4_domains TEXT NOT NULL DEFAULT '[]';
