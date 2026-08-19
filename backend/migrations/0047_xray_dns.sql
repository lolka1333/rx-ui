-- Operator-chosen DNS for the core.
--
-- Until now the panel emitted no `dns` section at all, which leaves xray on the
-- host resolver. That is a fine default and stays the default (no servers = no
-- section emitted, byte-identical config to before), but it is the wrong answer
-- in two cases the panel actively encourages:
--
--   * `IPOnDemand` / `IPIfNonMatch` routing resolves every domain the IP rules
--     touch, so the node's ISP resolver sees the whole browsing list;
--   * a node abroad answers CDN queries from its own region, which is exactly
--     what the operator does NOT want when routing by geoip.
--
-- `xray_dns_servers` is a JSON array of objects mirroring xray's own
-- `NameServerConfig`: an address plus the per-server knobs that make split
-- horizon DNS possible (`domains` picks which names this server answers,
-- `expect_ips` / `unexpected_ips` filter the answer, `skip_fallback` keeps it
-- out of the fallback chain). Order is the operator's: the core walks the list.
-- A server carrying nothing but an address is emitted as a plain string, so a
-- simple setup still produces the simple config anyone would write by hand.
--
-- The scalar columns are the section's own fields. Defaults are the core's own
-- defaults, so turning DNS on without touching them keeps xray's behaviour.
ALTER TABLE panel_settings ADD COLUMN xray_dns_servers TEXT NOT NULL DEFAULT '[]';
ALTER TABLE panel_settings ADD COLUMN xray_dns_hosts TEXT NOT NULL DEFAULT '[]';
ALTER TABLE panel_settings ADD COLUMN xray_dns_query_strategy TEXT NOT NULL DEFAULT 'UseIP';
ALTER TABLE panel_settings ADD COLUMN xray_dns_client_ip TEXT NOT NULL DEFAULT '';
-- Routing tag stamped on the resolver's OWN queries, so a rule can send them
-- somewhere specific — on a relay that is how DNS is kept off the tunnel.
ALTER TABLE panel_settings ADD COLUMN xray_dns_tag TEXT NOT NULL DEFAULT '';
ALTER TABLE panel_settings ADD COLUMN xray_dns_disable_cache INTEGER NOT NULL DEFAULT 0;
ALTER TABLE panel_settings ADD COLUMN xray_dns_disable_fallback INTEGER NOT NULL DEFAULT 0;
ALTER TABLE panel_settings ADD COLUMN xray_dns_disable_fallback_if_match INTEGER NOT NULL DEFAULT 0;
ALTER TABLE panel_settings ADD COLUMN xray_dns_parallel_query INTEGER NOT NULL DEFAULT 0;
ALTER TABLE panel_settings ADD COLUMN xray_dns_use_system_hosts INTEGER NOT NULL DEFAULT 0;
ALTER TABLE panel_settings ADD COLUMN xray_dns_serve_stale INTEGER NOT NULL DEFAULT 0;
ALTER TABLE panel_settings ADD COLUMN xray_dns_serve_expired_ttl INTEGER NOT NULL DEFAULT 0;
