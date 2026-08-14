-- Geofile sources, independent of the xray release archive.
--
-- Until now geoip.dat / geosite.dat only ever arrived inside the xray release
-- zip (see `xray::installer`), so they were pinned to whatever the core shipped
-- and could not be refreshed without reinstalling the binary. These columns let
-- the operator point the panel at a rules repository instead, keep the files
-- current, and see whether the ones on disk are still the ones that source
-- publishes.
--
-- `geo_source` is an id, not a URL: the presets' asset paths belong in code
-- where they can be corrected in a release, while the DB records the CHOICE.
-- 'xray' preserves today's behaviour and stays the default, so an existing
-- install changes nothing until the operator picks otherwise.

ALTER TABLE panel_settings ADD COLUMN geo_source TEXT NOT NULL DEFAULT 'xray';

-- Only consulted when geo_source = 'custom'. Two URLs rather than one base:
-- operators mirror these files behind arbitrary paths, and guessing a layout
-- from a prefix is how a "custom" option stops being custom.
ALTER TABLE panel_settings ADD COLUMN geo_custom_geoip_url TEXT NOT NULL DEFAULT '';
ALTER TABLE panel_settings ADD COLUMN geo_custom_geosite_url TEXT NOT NULL DEFAULT '';

-- Daily background refresh. Off by default: a panel that reaches out to the
-- internet on its own is a decision for the operator to make, not one to
-- inherit from an upgrade.
ALTER TABLE panel_settings ADD COLUMN geo_auto_update INTEGER NOT NULL DEFAULT 0;

-- SHA-256 of the bytes last written by the geofile updater, and when. Compared
-- against a freshly downloaded file to answer "did anything actually change?"
-- without diffing 30 MB of dat, and shown in the UI so the operator can tell a
-- stale file from a current one. Empty means "never updated from a source" —
-- i.e. the files are whatever the xray archive put there.
ALTER TABLE panel_settings ADD COLUMN geo_geoip_sha TEXT NOT NULL DEFAULT '';
ALTER TABLE panel_settings ADD COLUMN geo_geosite_sha TEXT NOT NULL DEFAULT '';
ALTER TABLE panel_settings ADD COLUMN geo_updated_at TEXT NOT NULL DEFAULT '';
