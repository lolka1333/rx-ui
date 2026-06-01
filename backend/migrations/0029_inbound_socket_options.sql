-- Per-inbound socket options (streamSettings.sockopt).
--
-- Carries trustedXForwardedFor (xray-core #6159 now warns when it is
-- unset on XHTTP/WS/HttpUpgrade inbounds — the header is otherwise
-- trusted implicitly and spoofable), plus TCP keepalive and MPTCP.
--
-- Default '{}' deserializes to an all-empty, inactive SocketOpt via the
-- struct-level #[serde(default)], so every existing inbound keeps an
-- unchanged xray wire config (no sockopt block emitted) until an
-- operator sets a value.
ALTER TABLE inbounds
    ADD COLUMN sockopt_config TEXT NOT NULL DEFAULT '{}';
