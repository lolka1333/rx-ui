-- Remaining `splithttp.Config` fields from xray-core's proto that other
-- panels (3x-ui, Marzban) expose under "Advanced". These are all anti-DPI
-- obfuscation knobs — padding placement / session-token placement /
-- sequence-counter placement / uplink wire shape. All nullable; absent
-- ⇒ xray uses its compile-time default (which is what every operator who
-- doesn't tune anti-DPI wants).
--
-- Note: this only adds the LITERAL fields from the proto. Operators
-- choose placement targets like "cookie" / "header" / "url-query" via
-- plain TEXT, because xray's accepted values evolve faster than we can
-- pin enums and an unknown value here would be a hard 400 instead of
-- a graceful pass-through to xray.

ALTER TABLE inbounds ADD COLUMN xhttp_x_padding_obfs_mode INTEGER; -- 0/1, null = default
ALTER TABLE inbounds ADD COLUMN xhttp_x_padding_key TEXT;
ALTER TABLE inbounds ADD COLUMN xhttp_x_padding_header TEXT;
ALTER TABLE inbounds ADD COLUMN xhttp_x_padding_placement TEXT;   -- "header"/"cookie"/...
ALTER TABLE inbounds ADD COLUMN xhttp_x_padding_method TEXT;      -- obfuscation method name

ALTER TABLE inbounds ADD COLUMN xhttp_uplink_http_method TEXT;    -- "POST"/"PUT"/...

ALTER TABLE inbounds ADD COLUMN xhttp_session_placement TEXT;     -- "cookie"/"header"/...
ALTER TABLE inbounds ADD COLUMN xhttp_session_key TEXT;

ALTER TABLE inbounds ADD COLUMN xhttp_seq_placement TEXT;
ALTER TABLE inbounds ADD COLUMN xhttp_seq_key TEXT;

ALTER TABLE inbounds ADD COLUMN xhttp_uplink_data_placement TEXT;
ALTER TABLE inbounds ADD COLUMN xhttp_uplink_data_key TEXT;

ALTER TABLE inbounds ADD COLUMN xhttp_uplink_chunk_size TEXT;     -- range "N" or "N-M"
ALTER TABLE inbounds ADD COLUMN xhttp_server_max_header_bytes INTEGER;
