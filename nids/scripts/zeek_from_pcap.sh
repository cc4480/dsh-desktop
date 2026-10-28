#!/usr/bin/env bash
# Turn a lab capture into the JSON Zeek logs this pipeline reads.
#   scripts/zeek_from_pcap.sh capture.pcap data/lab/real
# Uses the official Zeek image so nothing needs installing on the host.
set -euo pipefail
pcap=$(realpath "$1"); out=${2:-data/lab/real}
mkdir -p "$out"; out=$(realpath "$out")
docker run --rm --network none -v "$(dirname "$pcap")":/in:ro -v "$out":/out -w /out zeek/zeek:lts \
  zeek -C -r "/in/$(basename "$pcap")" LogAscii::use_json=T local
echo "Zeek logs in $out:"; ls "$out"
