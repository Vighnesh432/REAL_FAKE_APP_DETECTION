#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"
[ -d .venv ] || python3 -m venv .venv
source .venv/bin/activate
pip install -q -r requirements.txt
[ -f data/apps_dataset.csv ] || python data/generate_dataset.py --n 6000 --noise 0.02 --out data/apps_dataset.csv
[ -f models_store/model.joblib ] || python -m app.ml.train --data data/apps_dataset.csv
exec uvicorn app.main:app --reload --port 8000
