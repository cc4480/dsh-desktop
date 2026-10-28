#!/usr/bin/env bash
# The whole demo floor in one command: lab data -> anomaly model -> pipeline -> dashboard.
set -euo pipefail
cd "$(dirname "$0")/.."
python -m nids lab
python -m nids train-anomaly data/lab/baseline
python -m nids run data/lab/demo --fresh "$@"
python -m nids evaluate data/lab/demo
: "${NIDS_DASHBOARD_PASSWORD:?set NIDS_DASHBOARD_PASSWORD to open the dashboard}"
exec streamlit run dashboard/app.py
