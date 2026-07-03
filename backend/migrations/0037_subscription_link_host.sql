-- Host for the subscription URL itself (the `/sub/{token}` link), kept
-- separate from `sub_host_override` (the server address baked into each
-- config). Empty ≡ fall back to the panel's own address (the origin the
-- admin opens). Lets the shareable subscription link point at the panel
-- domain while the configs inside it dial a different tunnel / CDN host.
ALTER TABLE panel_settings ADD COLUMN sub_link_host TEXT NOT NULL DEFAULT '';

-- Backfill: before this split, `sub_host_override` doubled as the host of
-- the subscription URL (the UI built the /sub/ link from it). Seed the new
-- column with it so an existing install's shareable link is unchanged after
-- upgrade — otherwise the empty default would silently repoint the link to
-- the admin's browsing origin, which may be a private / unreachable host.
-- Fresh installs have an empty override, so this is a no-op there.
UPDATE panel_settings SET sub_link_host = sub_host_override WHERE sub_link_host = '';
