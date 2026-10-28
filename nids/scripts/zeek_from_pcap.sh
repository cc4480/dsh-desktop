#!/usr/bin/env bash
# Turn a capture into the JSON Zeek logs this pipeline reads, with JA4/JA3 and Community IDs.
#   scripts/zeek_from_pcap.sh capture.pcap data/lab/real
# Builds the lab's sensor image (zeek/zeek:lts + fingerprinting packages) on first use.
set -euo pipefail
here=$(cd "$(dirname "$0")/.." && pwd)
pcap=$(realpath "$1"); out=${2:-data/lab/real}
mkdir -p "$out"; out=$(realpath "$out")
docker build -q -t nids-zeek-sensor "$here/lab/sensor" >/dev/null
docker run --rm --network none -v "$(dirname "$pcap")":/in:ro -v "$out":/out -w /out nids-zeek-sensor \
  zeek -C -r "/in/$(basename "$pcap")" LogAscii::use_json=T local
echo "Zeek logs in $out:"; ls "$out"
