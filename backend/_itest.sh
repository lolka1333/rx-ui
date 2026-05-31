#!/usr/bin/env bash
# End-to-end: panel REST API -> xray (server inbound via gRPC AddInbound)
#             -> xray (client) -> internet. Exercises the new sockopt path.
set -u
ROOT="C:/Users/admin/Downloads/gthubdelta"
BK="$ROOT/rx-ui/backend"
XRAY="$ROOT/xray.exe"
TDIR="$BK/_itest"
PANEL=127.0.0.1:8088
INPORT=2443
SOCKS=10897

rm -rf "$TDIR"; mkdir -p "$TDIR/data"
cd "$BK"

echo "=== [1] launch panel (release) on $PANEL, real xray=$XRAY ==="
DATABASE_URL="sqlite://_itest/data/panel.db" \
XRAY_BINARY="$XRAY" \
PANEL_HOST=127.0.0.1 PANEL_PORT=8088 \
JWT_SECRET=itest_secret_0123456789_0123456789_0123456789 \
RUST_LOG=rx_ui=info,sqlx=warn \
./target/release/rx-ui.exe > "$TDIR/panel.log" 2>&1 &
PANEL_PID=$!
echo "panel pid=$PANEL_PID"

echo "=== [2] wait for /api/health ==="
ok=0
for i in $(seq 1 60); do
  if curl -s --max-time 2 "http://$PANEL/api/health" 2>/dev/null | grep -q ok; then ok=1; break; fi
  sleep 0.5
done
[ "$ok" = 1 ] && echo "health OK" || { echo "HEALTH FAIL"; tail -40 "$TDIR/panel.log"; kill $PANEL_PID 2>/dev/null; exit 1; }

echo "=== [3] login admin/admin ==="
LOGIN=$(curl -s --max-time 5 -X POST "http://$PANEL/api/auth/login" -H 'Content-Type: application/json' -d '{"username":"admin","password":"admin"}')
TOKEN=$(echo "$LOGIN" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
[ -n "$TOKEN" ] && echo "token len=${#TOKEN}" || { echo "LOGIN FAIL: $LOGIN"; kill $PANEL_PID 2>/dev/null; exit 1; }
AUTH="Authorization: Bearer $TOKEN"

echo "=== [4] create VLESS+TCP+none inbound WITH sockopt (trustedXForwardedFor+keepalive) on :$INPORT ==="
INBODY='{
  "tag":"itest-in","listen":"127.0.0.1","port":'"$INPORT"',
  "protocol":{"kind":"vless","flow":"none","encryption_mode":"none","encryption_auth":null,"encryption_xor_mode":null,"encryption_seconds_from":null,"encryption_seconds_to":null,"encryption_padding":null,"encryption_server_key":null,"encryption_client_key":null,"fallbacks":[]},
  "transport":{"kind":"tcp"},
  "security":{"kind":"none"},
  "sniffing":{"enabled":false,"dest_override":[]},
  "finalmask":{"kind":"none"},
  "sockopt":{"trusted_x_forwarded_for":["127.0.0.1","10.0.0.0/8"],"tcp_keep_alive_interval":15,"tcp_keep_alive_idle":30,"tcp_mptcp":false}
}'
INRESP=$(curl -s --max-time 10 -w "\n__HTTP__%{http_code}" -X POST "http://$PANEL/api/inbounds" -H "$AUTH" -H 'Content-Type: application/json' -d "$INBODY")
INCODE=$(echo "$INRESP" | sed -n 's/.*__HTTP__//p')
INJSON=$(echo "$INRESP" | sed 's/__HTTP__.*//')
echo "create inbound HTTP=$INCODE"
INBOUND_ID=$(echo "$INJSON" | sed -n 's/.*"id":"\([^"]*\)".*/\1/p' | head -1)
echo "inbound_id=$INBOUND_ID"
[ "$INCODE" = "201" ] || [ "$INCODE" = "200" ] || { echo ">>> INBOUND CREATE FAILED"; echo "$INJSON" | head -c 800; echo; tail -25 "$TDIR/panel.log"; kill $PANEL_PID 2>/dev/null; exit 1; }

echo "=== [5] verify sockopt round-tripped via GET /api/inbounds ==="
GETIN=$(curl -s --max-time 5 "http://$PANEL/api/inbounds" -H "$AUTH")
echo "$GETIN" | grep -q '10.0.0.0/8' && echo "SOCKOPT PERSISTED OK" || echo "SOCKOPT MISMATCH: $(echo "$GETIN" | grep -o '"sockopt":[^}]*}')"

echo "=== [6] create client (global route) ==="
CLBODY='{"inbound_id":"'"$INBOUND_ID"'","email":"itest-user"}'
CLRESP=$(curl -s --max-time 10 -w "\n__HTTP__%{http_code}" -X POST "http://$PANEL/api/clients" -H "$AUTH" -H 'Content-Type: application/json' -d "$CLBODY")
CLCODE=$(echo "$CLRESP" | sed -n 's/.*__HTTP__//p')
CLJSON=$(echo "$CLRESP" | sed 's/__HTTP__.*//')
echo "create client HTTP=$CLCODE"
CLIENT_ID=$(echo "$CLJSON" | sed -n 's/.*"id":"\([^"]*\)".*/\1/p' | head -1)
UUID=$(echo "$CLJSON" | sed -n 's/.*"uuid":"\([^"]*\)".*/\1/p' | head -1)
echo "client_id=$CLIENT_ID uuid=$UUID"
[ -n "$UUID" ] || { echo "CLIENT CREATE FAIL: $CLJSON"; tail -20 "$TDIR/panel.log"; kill $PANEL_PID 2>/dev/null; exit 1; }

echo "=== [7] fetch share-link ==="
SL=$(curl -s --max-time 5 "http://$PANEL/api/clients/$CLIENT_ID/share-link" -H "$AUTH")
echo "share-link: $(echo "$SL" | sed -n 's/.*"link":"\([^"]*\)".*/\1/p' | head -c 200)"

echo "=== [8] build client xray cfg (socks $SOCKS -> 127.0.0.1:$INPORT) ==="
cat > "$TDIR/client.json" <<EOF
{ "log":{"loglevel":"warning"},
  "inbounds":[{"tag":"s","listen":"127.0.0.1","port":$SOCKS,"protocol":"socks","settings":{"udp":true}}],
  "outbounds":[{"tag":"proxy","protocol":"vless","settings":{"vnext":[{"address":"127.0.0.1","port":$INPORT,"users":[{"id":"$UUID","encryption":"none"}]}]},"streamSettings":{"network":"tcp","security":"none"}}]
}
EOF
"$XRAY" run -test -config "$TDIR/client.json" >/dev/null 2>&1 && echo "client cfg valid" || { echo "client cfg INVALID"; kill $PANEL_PID 2>/dev/null; exit 1; }
"$XRAY" run -config "$TDIR/client.json" > "$TDIR/client.log" 2>&1 &
CXPID=$!
echo "client xray pid=$CXPID"
sleep 2

echo "=== [9] traffic through chain: client-xray -> panel-xray inbound -> freedom -> internet ==="
EGRESS=""
for i in 1 2 3; do
  R=$(curl -s -o /dev/null -w "%{http_code}" --max-time 15 --socks5-hostname 127.0.0.1:$SOCKS https://api.ipify.org 2>/dev/null)
  echo "try$i: http=$R"
  if [ "$R" = "200" ]; then EGRESS=$(curl -s --max-time 15 --socks5-hostname 127.0.0.1:$SOCKS https://api.ipify.org 2>/dev/null); break; fi
  sleep 1
done
echo "egress via chain: $EGRESS"

echo "=== cleanup ==="
kill $CXPID 2>/dev/null
kill $PANEL_PID 2>/dev/null
sleep 1
echo "=== RESULT ==="
[ -n "$EGRESS" ] && echo "PASS: created inbound+client via API, traffic flows through panel-managed xray. egress=$EGRESS" || { echo "FAIL: no egress"; echo "--- client.log ---"; tail -8 "$TDIR/client.log"; echo "--- panel.log (xray lines) ---"; grep -iE "xray|inbound|AddInbound|reconc" "$TDIR/panel.log" | tail -10; }
