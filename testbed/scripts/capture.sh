#!/bin/sh
# Captures IPsec traffic to a pcap file.
#
# Run inside a testbed peer, e.g.:
#   docker compose exec vpn-client /scripts/capture.sh /scripts/capture.pcap 30
#
# Because ./scripts is mounted into the containers, the resulting file also
# appears on the host at testbed/scripts/<name>.pcap and can be uploaded to the
# analyzer dashboard.
#
# Usage: capture.sh [output-file] [seconds] [interface]
OUT="${1:-/scripts/capture.pcap}"
DURATION="${2:-30}"
IFACE="${3:-any}"

echo "[capture] interface=$IFACE duration=${DURATION}s output=$OUT"
echo "[capture] filter: IKE (udp 500/4500), ESP (proto 50), AH (proto 51)"

timeout "$DURATION" tcpdump -i "$IFACE" -s 0 -w "$OUT" \
    '(udp port 500 or udp port 4500 or ip proto 50 or ip proto 51)'

if [ -f "$OUT" ]; then
    echo "[capture] wrote $OUT"
    ls -l "$OUT"
else
    echo "[capture] no file produced" >&2
    exit 1
fi
