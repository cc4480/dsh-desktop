#!/usr/bin/env bash
# The whole demo in one command: lab data -> models + profile -> pipeline -> evaluation -> dashboard.
set -euo pipefail
cd "$(dirname "$0")/.."
python -m nids lab
python -m nids train data/lab/baseline
python -m nids run data/lab/demo --fresh "$@"
python -m nids evaluate data/lab/demo
if [ ! -f config/users.yaml ] && [ -z "${NIDS_DASHBOARD_PASSWORD:-}" ]; then
  echo "add a login first (python -m nids add-user <name> --role approver) or set NIDS_DASHBOARD_PASSWORD" >&2
  exit 1
fi
exec streamlit run dashboard/app.py
