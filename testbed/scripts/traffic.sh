#!/bin/sh
# Generates traffic that traverses the IPsec tunnel (client -> server).
# Usage: sh traffic.sh [target-ip] [iterations]
TARGET="${1:-10.0.1.3}"
ITERATIONS="${2:-0}"   # 0 = run forever

echo "[traffic] generating tunnel traffic to $TARGET"

i=0
while true; do
    i=$((i + 1))

    # ICMP - easy to spot in the capture
    ping -c 5 "$TARGET" >/dev/null 2>&1

    # A little noise on common ports (UDP probes; replies are optional)
    for port in 53 123 500 4500 5060; do
        echo "probe" | nc -u -w 1 "$TARGET" "$port" >/dev/null 2>&1
    done

    echo "[traffic] round $i complete"
    [ "$ITERATIONS" -gt 0 ] && [ "$i" -ge "$ITERATIONS" ] && break

    sleep 2
done

echo "[traffic] finished"
