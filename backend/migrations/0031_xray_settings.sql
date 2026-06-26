-- xray engine settings (outbound/routing). These live in the bootstrap
-- config (config_gen), so they only take effect on an xray restart — the
-- panel regenerates the bootstrap from these columns on every restart.
--
--   * xray_freedom_strategy  — domainStrategy of the `direct` freedom
--     outbound (AsIs / UseIP* / ForceIP*). Controls how the egress
--     resolves destination domains (e.g. UseIPv4 forces IPv4 egress).
--   * xray_routing_strategy  — domainStrategy of the routing block
--     (AsIs / IPIfNonMatch / IPOnDemand). Controls whether routing rules
--     match on the resolved IP, needed for geoip/geosite IP rules.
--   * xray_test_url          — URL the "test outbound" button fetches
--     from the server to confirm the egress can reach the internet.
ALTER TABLE panel_settings ADD COLUMN xray_freedom_strategy TEXT NOT NULL DEFAULT 'AsIs';
ALTER TABLE panel_settings ADD COLUMN xray_routing_strategy TEXT NOT NULL DEFAULT 'AsIs';
ALTER TABLE panel_settings ADD COLUMN xray_test_url TEXT NOT NULL DEFAULT 'https://www.google.com/generate_204';
