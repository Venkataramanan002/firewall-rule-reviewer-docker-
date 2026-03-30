#!/usr/bin/env bash
set -euo pipefail

export PATH="/opt/venv/bin:${PATH}"

mkdir -p /app/model

echo "[start] Launching backend on :8000"
uvicorn main:app --host 0.0.0.0 --port 8000 &
BACKEND_PID=$!

echo "[start] Launching frontend on :8501"
nginx -g 'daemon off;' &
NGINX_PID=$!

term_handler() {
  echo "[start] Stopping services..."
  kill "${BACKEND_PID}" "${NGINX_PID}" 2>/dev/null || true
}

trap term_handler INT TERM

# Exit if either process dies
wait -n "${BACKEND_PID}" "${NGINX_PID}"
term_handler
exit 1
