-- Full coverage of xray's `splithttp.Config` knobs that 3x-ui/Marzban
-- typically expose. Every field is nullable — operators stay on xray's
-- compile-time defaults until they explicitly set a value, so adding the
-- columns is a no-op for existing inbounds.
--
-- Range-typed proto fields (`RangeConfig{from, to}`) are stored as plain
-- TEXT in the operator's format: a single number means `from==to`, a
-- dashed pair means a range. The converter parses these into the proto
-- representation at push time. We use TEXT rather than two int columns
-- per range because every range is optional and operator-typed: a
-- single, nullable cell is cheaper than two `(_min, _max)` pairs that
-- have to be either both set or both null.

-- HTTP/wire-shape options
ALTER TABLE inbounds ADD COLUMN xhttp_headers TEXT;                 -- JSON object: {"X-Header": "v"}
ALTER TABLE inbounds ADD COLUMN xhttp_x_padding_bytes TEXT;         -- range, e.g. "100-1000"
ALTER TABLE inbounds ADD COLUMN xhttp_no_grpc_header INTEGER;       -- 0/1, null = default
ALTER TABLE inbounds ADD COLUMN xhttp_no_sse_header INTEGER;        -- 0/1, null = default

-- Stream-control (per packet-up / stream-up mode tuning)
ALTER TABLE inbounds ADD COLUMN xhttp_sc_max_each_post_bytes TEXT;  -- range
ALTER TABLE inbounds ADD COLUMN xhttp_sc_min_posts_interval_ms TEXT;-- range
ALTER TABLE inbounds ADD COLUMN xhttp_sc_max_buffered_posts INTEGER;-- single int
ALTER TABLE inbounds ADD COLUMN xhttp_sc_stream_up_server_secs TEXT;-- range

-- XMux (multiplexing) — six knobs from XmuxConfig in the proto
ALTER TABLE inbounds ADD COLUMN xhttp_xmux_max_concurrency TEXT;    -- range
ALTER TABLE inbounds ADD COLUMN xhttp_xmux_max_connections TEXT;    -- range
ALTER TABLE inbounds ADD COLUMN xhttp_xmux_c_max_reuse_times TEXT;  -- range
ALTER TABLE inbounds ADD COLUMN xhttp_xmux_h_max_request_times TEXT;-- range
ALTER TABLE inbounds ADD COLUMN xhttp_xmux_h_max_reusable_secs TEXT;-- range
ALTER TABLE inbounds ADD COLUMN xhttp_xmux_h_keep_alive_period INTEGER; -- single int
