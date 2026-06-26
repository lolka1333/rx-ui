-- Operator-defined routing rules + the full evaluation order. Like the 0032
-- columns these live in the bootstrap config, so they apply on an xray restart.
--
--   * xray_custom_rules — JSON array of rule objects (see models::RoutingRule):
--     condition matchers (domain/ip/port/network/protocol/source/inbound/user)
--     plus a single outbound_tag target (direct / blocked / direct-ipv4).
--   * xray_rule_order — JSON array of order tokens in evaluation order: the
--     system keys ('api','bittorrent','blocked_domains','blocked_ips','ipv4')
--     and custom rule ids. Lets the operator reorder built-in and custom rules
--     freely (first-match-wins).
ALTER TABLE panel_settings ADD COLUMN xray_custom_rules TEXT NOT NULL DEFAULT '[]';
ALTER TABLE panel_settings ADD COLUMN xray_rule_order TEXT NOT NULL DEFAULT '[]';
