#!/usr/bin/env bash
# Build and run the isolated Docker lab, leaving Zeek JSON logs (+ ground truth) on disk.
#
#   lab/run_lab.sh baseline [SECONDS]   benign only, default 1200 s  -> data/lab-docker/baseline
#   lab/run_lab.sh attack               benign + scripted attacks    -> data/lab-docker/attack
#
# Then:
#   python -m nids train data/lab-docker/baseline --out models/anomaly-lab.joblib \
#       --profile-out models/profile-lab.json
#   python -m nids evaluate data/lab-docker/attack --assets config/assets.lab.yaml \
#       --anomaly-model models/anomaly-lab.joblib --profile models/profile-lab.json
set -euo pipefail
cd "$(dirname "$0")"
mode=${1:?usage: run_lab.sh baseline [seconds] | attack}
root=$(cd .. && pwd)
export LAB_OUT=${LAB_OUT:-$root/data/lab-docker/$mode}
rm -rf "$LAB_OUT" && mkdir -p "$LAB_OUT"

cleanup() { docker compose --profile attack down --remove-orphans >/dev/null 2>&1 || true; }
trap cleanup EXIT
cleanup
docker compose --profile attack build

case "$mode" in
  baseline)
    docker compose up -d target sensor recorder client
    echo "capturing benign baseline for ${2:-1200}s ..."
    sleep "${2:-1200}"
    ;;
  attack)
    docker compose --profile attack up -d
    echo "attack scenario running (about 20 min) ..."
    docker wait "$(docker compose ps -aq attacker)" "$(docker compose ps -aq implant)" >/dev/null
    sleep 15   # let the tail of the scenario reach the sensor
    ;;
  *) echo "unknown mode $mode" >&2; exit 2 ;;
esac

docker compose stop -t 60 sensor recorder client   # SIGTERM: Zeek flushes open connections
echo "logs in $LAB_OUT:"; ls -la "$LAB_OUT"
