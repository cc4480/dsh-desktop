# Shared helpers. Ground truth is appended as JSON lines to /out/ground_truth.jsonl,
# timestamped with the same host clock Zeek uses.
TARGET=172.28.0.10
ME=$(hostname -i | awk '{print $1}')
GT=/out/ground_truth.jsonl
now() { date +%s.%N; }
# gt ATTACK DST_JSON START END EXPECT ATTACK_ID_JSON
gt() {
  printf '{"attack":"%s","src":"%s","dst":%s,"start":%s,"end":%s,"expect":"%s","attack_id":%s}\n' \
    "$1" "$ME" "$2" "$3" "$4" "$5" "$6" >> "$GT"
}
