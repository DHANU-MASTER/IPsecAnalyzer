#!/usr/bin/env bash
# =============================================================================
# One-command StrongSwan testbed run (Linux host with Docker + NET_ADMIN).
#
#   ./run_testbed.sh [capture-seconds]
#
# Whole flow:
#   1. Starts the two-peer StrongSwan testbed (docker compose).
#   2. Waits until the IKEv2 tunnel is ESTABLISHED.
#   3. Drives real traffic through the tunnel.
#   4. Captures a pcap (IKE 500/4500, ESP proto 50) while traffic flows.
#   5. Copies the capture to the host and prints the analyzer upload command.
#
# The capture files land in testbed/scripts/ (via the scripts volume) and can
# be renamed cipher__mode__label.pcap and dropped into IPsecAnalyzer/dataset/
# for the real-data retraining path.
# =============================================================================
set -euo pipefail

CAPTURE_SECONDS="${1:-30}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "== [1/5] starting testbed containers =="
docker compose up -d --build
sleep 5

echo "== [2/5] waiting for IKEv2 tunnel establishment =="
TUNNEL_UP=0
for i in $(seq 1 60); do
    if docker compose exec -T vpn-client ipsec status 2>/dev/null | grep -q "INSTALLED"; then
        TUNNEL_UP=1
        break
    fi
    sleep 2
done
if [ "$TUNNEL_UP" != "1" ]; then
    echo "ERROR: tunnel did not come up in 120s. Debug with:" >&2
    echo "  docker compose exec vpn-client ipsec statusall" >&2
    echo "  docker compose logs vpn-client | tail -50" >&2
    docker compose logs --tail 20 vpn-client vpn-server >&2 || true
    exit 1
fi
docker compose exec -T vpn-client ipsec status || true

echo "== [3/5] driving traffic through the tunnel =="
docker compose exec -T vpn-client sh -c '
    ping -c 10 -i 0.3 10.0.1.3 >/dev/null 2>&1 || true
    for i in $(seq 1 40); do
        dd if=/dev/urandom bs=1024 count=8 2>/dev/null | nc -q1 -u 10.0.1.3 9999 || true
    done
    ping -c 10 -i 0.3 10.0.1.3 >/dev/null 2>&1 || true
' &
TRAFFIC_PID=$!
sleep 2

echo "== [4/5] capturing ${CAPTURE_SECONDS}s of IPsec traffic =="
docker compose exec -T vpn-client /scripts/capture.sh /scripts/tunnel_capture.pcap "$CAPTURE_SECONDS" || true
wait $TRAFFIC_PID 2>/dev/null || true

STAMP="$(date +%Y%m%d-%H%M%S)"
HOST_FILE="$ROOT/scripts/tunnel_capture_${STAMP}.pcap"
[ -f "$ROOT/scripts/tunnel_capture.pcap" ] && cp "$ROOT/scripts/tunnel_capture.pcap" "$HOST_FILE"

echo "== [5/5] done =="
echo "Capture on host: $HOST_FILE"
echo
echo "Upload to the analyzer:"
echo "  TOKEN=\$(curl -s -X POST http://127.0.0.1:8080/auth/login -H 'Content-Type: application/json' \\"
echo "    -d '{\"username\":\"admin\",\"password\":\"Admin@123\"}' | sed -n 's/.*\"token\":\"\\([^\"]*\\)\".*/\\1/p')"
echo "  curl -X POST http://127.0.0.1:8080/api/analyze/pcap -H \"Authorization: Bearer \$TOKEN\" -F \"file=@$HOST_FILE\""
echo
echo "Label it for model training (edit cipher/mode to match conn tunnel-aes128 = AES-128/Tunnel):"
echo "  cp $HOST_FILE IPsecAnalyzer/dataset/AES-128__Tunnel__testbed-${STAMP}.pcap"
echo "  curl -X POST http://127.0.0.1:8080/api/ml/retrain -H \"Authorization: Bearer \$TOKEN\""
