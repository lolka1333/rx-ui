-- The key-value `settings` table from 0001_init was superseded by the typed
-- single-row `panel_settings` (0019) and has never been read or written since:
-- no query in backend/src references it. 0001_init is left untouched — its
-- checksum is recorded in _sqlx_migrations.
DROP TABLE IF EXISTS settings;
