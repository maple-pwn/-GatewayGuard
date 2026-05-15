#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

if [ ! -d ".relay-venv" ]; then
  python3 -m venv .relay-venv
fi

source .relay-venv/bin/activate
python -m pip install -q --upgrade pip
python -m pip install -q "fastapi==0.115.0" "uvicorn[standard]==0.30.0" "pydantic==2.9.0"

exec uvicorn relay_server:app --host 0.0.0.0 --port "${GATEWAY_GUARD_RELAY_PORT:-8000}"
