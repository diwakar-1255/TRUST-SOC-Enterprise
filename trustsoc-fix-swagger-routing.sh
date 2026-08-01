#!/usr/bin/env bash
set -Eeuo pipefail

cd "${1:-$(pwd)}"

if [[ ! -f compose.yaml || ! -f apps/api/trustsoc/main.py ]]; then
  echo "ERROR: Run this from the TRUST-SOC-Enterprise project folder."
  exit 1
fi

timestamp="$(date +%Y%m%d-%H%M%S)"
cp apps/api/trustsoc/main.py "apps/api/trustsoc/main.py.backup-$timestamp"

python3 - <<'PY'
from pathlib import Path

path = Path("apps/api/trustsoc/main.py")
text = path.read_text()

if 'root_path="/api"' not in text:
    marker = '    lifespan=lifespan,\n'
    replacement = marker + '    root_path="/api",\n'
    if marker not in text:
        raise SystemExit("Could not safely locate the FastAPI constructor.")
    text = text.replace(marker, replacement, 1)

path.write_text(text)
print("Configured FastAPI public root path as /api.")
PY

python3 -m py_compile apps/api/trustsoc/main.py
docker compose config >/dev/null

echo "Rebuilding and recreating only the API container..."
docker compose build api
docker compose up -d --no-deps --force-recreate api

echo "Waiting for API health..."
for attempt in $(seq 1 30); do
  status="$(docker inspect --format='{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' trust-soc-api-1 2>/dev/null || true)"
  echo "Attempt $attempt: ${status:-unknown}"
  [[ "$status" == "healthy" ]] && break
  sleep 3
done

status="$(docker inspect --format='{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' trust-soc-api-1 2>/dev/null || true)"
if [[ "$status" != "healthy" ]]; then
  echo "API did not become healthy. Recent logs:"
  docker compose logs --no-color --tail=150 api || true
  exit 2
fi

echo
echo "Testing routed OpenAPI document..."
curl --fail --silent --show-error http://localhost/api/openapi.json >/dev/null

echo "Testing Swagger page..."
curl --fail --silent --show-error http://localhost/api/docs >/dev/null

echo
echo "Swagger routing repaired successfully."
echo "Open: http://localhost/api/docs"
