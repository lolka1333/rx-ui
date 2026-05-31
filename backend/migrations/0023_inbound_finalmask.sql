-- FinalMask config per inbound. Stores the operator's wire-level
-- obfuscation choice as a tagged-enum JSON blob (matches the rest of
-- the typed layers — protocol/transport/security/sniffing).
--
-- Defaults to `{"kind":"none"}` so existing rows continue to behave
-- exactly as before (no `streamSettings.finalmask` in the xray
-- handler, no `fm=` param in the share-link). The operator opts in
-- per inbound via the FinalMask tab on the inbound modal.

ALTER TABLE inbounds
  ADD COLUMN finalmask_config TEXT NOT NULL DEFAULT '{"kind":"none"}';
