#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
[[ -f .env ]] || ./scripts/bootstrap.sh
docker compose pull postgres redis gateway otel-collector prometheus grafana || true
docker compose up -d --build
printf '\nTRUST-SOC: http://localhost\nAPI docs: http://localhost/api/docs\nGrafana: http://localhost:3001\nPrometheus: http://localhost:9090\n'
docker compose ps
