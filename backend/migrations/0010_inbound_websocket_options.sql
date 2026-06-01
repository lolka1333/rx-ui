-- Power-user WebSocket knobs. xray's `websocket.Config` exposes a few
-- fields beyond path/host that the panel didn't surface in 0008. Adding
-- them as nullable so existing ws inbounds keep their xray-default
-- behaviour (no headers, proxy-protocol off, default heartbeat).
--
--   ws_headers                — JSON object {"X-Header": "v"} (same shape
--                               as xhttp_headers). Sent as a HashMap to
--                               xray's `websocket.Config.header` map.
--   ws_accept_proxy_protocol  — 0/1 bool. When true, xray expects the
--                               front-end (typically nginx / HAProxy) to
--                               prepend the PROXY-protocol header so
--                               xray can see the real client IP.
--   ws_heartbeat_period       — seconds between WS Ping frames (uint32).
--                               0 disables. Useful behind CDNs that drop
--                               idle WS connections after N seconds.
--
-- Note: WS `ed` (early data) is configured via the path query string
-- (`/ws?ed=2048`) — xray's JSON loader parses it out of `path`. We follow
-- the same convention: operator types `?ed=N` into the path field, no
-- separate column needed.

ALTER TABLE inbounds ADD COLUMN ws_headers TEXT;
ALTER TABLE inbounds ADD COLUMN ws_accept_proxy_protocol INTEGER;
ALTER TABLE inbounds ADD COLUMN ws_heartbeat_period INTEGER;
