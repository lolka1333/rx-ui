-- Operator-defined outbounds (egress / relay through another server). JSON
-- array of models::CustomOutbound. Pushed into the live xray over gRPC
-- (HandlerService.AddOutbound) — same "apply live, no restart" model as
-- inbounds — and re-pushed on boot / after an xray restart by the outbound
-- reconciler. Each enabled outbound's `tag` becomes a valid routing-rule
-- target (alongside the reserved direct/blocked/direct-ipv4).
ALTER TABLE panel_settings ADD COLUMN xray_custom_outbounds TEXT NOT NULL DEFAULT '[]';
