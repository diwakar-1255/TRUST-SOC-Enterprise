#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="${1:-$(pwd)}"
cd "$ROOT"

fail() {
  echo "ERROR: $*" >&2
  exit 1
}

[[ -f .env ]] || fail ".env not found. Run this from the TRUST-SOC-Enterprise folder."
[[ -f compose.yaml ]] || fail "compose.yaml not found."
[[ -d agents/collector/trust_agent ]] || fail "Collector source not found."

command -v curl >/dev/null || fail "curl is required."
command -v python3 >/dev/null || fail "python3 is required."

echo "Checking TRUST-SOC API..."
curl -fsS http://localhost/api/health/live >/dev/null ||
  fail "TRUST-SOC API is not reachable at http://localhost/api."

ADMIN_EMAIL="$(grep '^TRUSTSOC_BOOTSTRAP_ADMIN_EMAIL=' .env | cut -d= -f2-)"
ADMIN_PASSWORD="$(grep '^TRUSTSOC_BOOTSTRAP_ADMIN_PASSWORD=' .env | cut -d= -f2-)"

[[ -n "$ADMIN_EMAIL" ]] || fail "Bootstrap administrator email is missing from .env."
[[ -n "$ADMIN_PASSWORD" ]] || fail "Bootstrap administrator password is missing from .env."

LOGIN_PAYLOAD="$(
  ADMIN_EMAIL="$ADMIN_EMAIL" ADMIN_PASSWORD="$ADMIN_PASSWORD" python3 - <<'PY'
import json
import os

print(json.dumps({
    "email": os.environ["ADMIN_EMAIL"],
    "password": os.environ["ADMIN_PASSWORD"],
}))
PY
)"

LOGIN_RESPONSE="$(
  curl -fsS http://localhost/api/auth/login \
    -H 'Content-Type: application/json' \
    -d "$LOGIN_PAYLOAD"
)" || fail "Administrator authentication failed."

TOKEN="$(
  printf '%s' "$LOGIN_RESPONSE" |
    python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])'
)"

echo "Authenticated as $ADMIN_EMAIL."

HOST_NAME="$(hostname)"
OS_DESCRIPTION="$(python3 -c 'import platform; print(platform.platform())')"

ASSETS_JSON="$(
  curl -fsS http://localhost/api/assets \
    -H "Authorization: Bearer $TOKEN"
)"

ASSET_ID="$(
  printf '%s' "$ASSETS_JSON" |
    TARGET_HOST="$HOST_NAME" python3 -c '
import json
import os
import sys

target = os.environ["TARGET_HOST"]
items = json.load(sys.stdin)
print(next((str(item["id"]) for item in items if item["hostname"] == target), ""))
'
)"

if [[ -z "$ASSET_ID" ]]; then
  ASSET_PAYLOAD="$(
    HOST_NAME="$HOST_NAME" OS_DESCRIPTION="$OS_DESCRIPTION" python3 - <<'PY'
import json
import os

print(json.dumps({
    "hostname": os.environ["HOST_NAME"],
    "asset_type": "server",
    "operating_system": os.environ["OS_DESCRIPTION"],
    "criticality": 4,
    "owner": "TRUST-SOC Administrator",
    "tags": {
        "environment": "local-lab",
        "platform": "ubuntu-wsl",
        "telemetry": "signed",
        "protected_by": "TRUST-SOC",
    },
}))
PY
  )"

  ASSET_RESPONSE="$(
    curl -fsS http://localhost/api/assets \
      -H "Authorization: Bearer $TOKEN" \
      -H 'Content-Type: application/json' \
      -d "$ASSET_PAYLOAD"
  )" || fail "Failed to create Ubuntu asset."

  ASSET_ID="$(
    printf '%s' "$ASSET_RESPONSE" |
      python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])'
  )"

  echo "Created protected asset: $HOST_NAME ($ASSET_ID)"
else
  echo "Reusing protected asset: $HOST_NAME ($ASSET_ID)"
fi

COLLECTOR_DIR="$ROOT/agents/collector"
AGENT_ENV="$COLLECTOR_DIR/agent.env"
SOURCE_ID=""
SOURCE_SECRET=""

if [[ -f "$AGENT_ENV" ]]; then
  SOURCE_ID="$(grep '^TRUSTSOC_AGENT_SOURCE_ID=' "$AGENT_ENV" | cut -d= -f2- || true)"
  SOURCE_SECRET="$(grep '^TRUSTSOC_AGENT_SHARED_SECRET=' "$AGENT_ENV" | cut -d= -f2- || true)"
fi

if [[ -z "$SOURCE_ID" || -z "$SOURCE_SECRET" ||
      "$SOURCE_ID" == "REPLACE_WITH_SOURCE_UUID" ||
      "$SOURCE_SECRET" == "REPLACE_WITH_ONE_TIME_SECRET" ]]; then

  BASE_SOURCE_NAME="${HOST_NAME}-linux-collector"
  SOURCES_JSON="$(
    curl -fsS http://localhost/api/sources \
      -H "Authorization: Bearer $TOKEN"
  )"

  SOURCE_EXISTS="$(
    printf '%s' "$SOURCES_JSON" |
      TARGET_NAME="$BASE_SOURCE_NAME" python3 -c '
import json
import os
import sys

target = os.environ["TARGET_NAME"]
items = json.load(sys.stdin)
print("yes" if any(item["name"] == target for item in items) else "no")
'
  )"

  if [[ "$SOURCE_EXISTS" == "yes" ]]; then
    SOURCE_NAME="${BASE_SOURCE_NAME}-$(date +%Y%m%d%H%M%S)"
    echo "An older source named $BASE_SOURCE_NAME exists but its one-time secret is unavailable."
    echo "Creating a new signed source: $SOURCE_NAME"
  else
    SOURCE_NAME="$BASE_SOURCE_NAME"
  fi

  SOURCE_PAYLOAD="$(
    SOURCE_NAME="$SOURCE_NAME" ASSET_ID="$ASSET_ID" python3 - <<'PY'
import json
import os

print(json.dumps({
    "name": os.environ["SOURCE_NAME"],
    "source_type": "linux",
    "asset_id": os.environ["ASSET_ID"],
    "expected_heartbeat_seconds": 60,
    "expected_fields": [
        "hostname",
        "os",
        "agent_version",
        "status",
    ],
}))
PY
  )"

  SOURCE_RESPONSE="$(
    curl -fsS http://localhost/api/sources \
      -H "Authorization: Bearer $TOKEN" \
      -H 'Content-Type: application/json' \
      -d "$SOURCE_PAYLOAD"
  )" || fail "Failed to create telemetry source."

  SOURCE_ID="$(
    printf '%s' "$SOURCE_RESPONSE" |
      python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])'
  )"
  SOURCE_SECRET="$(
    printf '%s' "$SOURCE_RESPONSE" |
      python3 -c 'import json,sys; print(json.load(sys.stdin)["shared_secret"])'
  )"

  mkdir -p "$COLLECTOR_DIR/runtime"

  cat > "$AGENT_ENV" <<EOF
TRUSTSOC_AGENT_API_URL=http://localhost/api
TRUSTSOC_AGENT_SOURCE_ID=$SOURCE_ID
TRUSTSOC_AGENT_SHARED_SECRET=$SOURCE_SECRET
TRUSTSOC_AGENT_SOURCE_TYPE=linux
TRUSTSOC_AGENT_HEARTBEAT_SECONDS=30
TRUSTSOC_AGENT_VERIFY_TLS=false
TRUSTSOC_AGENT_SPOOL_PATH=./runtime/spool.jsonl
TRUSTSOC_AGENT_STATE_PATH=./runtime/state.json
EOF

  chmod 600 "$AGENT_ENV"
  echo "Created signed telemetry source: $SOURCE_ID"
  echo "Saved its one-time secret securely in agents/collector/agent.env."
else
  echo "Reusing collector configuration for source: $SOURCE_ID"
fi

cd "$COLLECTOR_DIR"
mkdir -p runtime

if [[ ! -x .venv/bin/python ]]; then
  echo "Creating collector virtual environment..."
  python3 -m venv .venv
fi

echo "Installing collector dependencies..."
.venv/bin/python -m pip install --disable-pip-version-check -q --upgrade pip
.venv/bin/python -m pip install --disable-pip-version-check -q -r requirements.txt

if [[ -f runtime/collector.pid ]]; then
  OLD_PID="$(cat runtime/collector.pid || true)"
  if [[ -n "$OLD_PID" ]] && kill -0 "$OLD_PID" 2>/dev/null; then
    echo "Stopping previous collector process $OLD_PID..."
    kill "$OLD_PID"
    sleep 2
  fi
fi

rm -f runtime/collector.log
nohup .venv/bin/python -m trust_agent.main > runtime/collector.log 2>&1 &
COLLECTOR_PID=$!
echo "$COLLECTOR_PID" > runtime/collector.pid

sleep 3
kill -0 "$COLLECTOR_PID" 2>/dev/null ||
  {
    echo "Collector failed to stay running. Log output:"
    cat runtime/collector.log || true
    exit 1
  }

echo "Collector started with PID $COLLECTOR_PID."
echo "Waiting for the first signed heartbeat..."

for attempt in $(seq 1 15); do
  SOURCES_JSON="$(
    curl -fsS http://localhost/api/sources \
      -H "Authorization: Bearer $TOKEN"
  )"

  SOURCE_STATUS="$(
    printf '%s' "$SOURCES_JSON" |
      SOURCE_ID="$SOURCE_ID" python3 -c '
import json
import os
import sys

source_id = os.environ["SOURCE_ID"]
items = json.load(sys.stdin)
item = next((x for x in items if str(x["id"]) == source_id), None)
if not item:
    print("missing|||")
else:
    print(
        f"{item['status']}|{item['trust_score']}|"
        f"{item.get('last_heartbeat_at') or ''}"
    )
'
  )"

  IFS='|' read -r STATUS TRUST LAST_HEARTBEAT <<< "$SOURCE_STATUS"

  if [[ "$STATUS" == "healthy" || "$STATUS" == "degraded" ]]; then
    echo
    echo "Ubuntu onboarding succeeded."
    echo "Source ID:       $SOURCE_ID"
    echo "Status:          $STATUS"
    echo "Trust score:     $TRUST"
    echo "Last heartbeat:  $LAST_HEARTBEAT"
    echo
    echo "Open TRUST-SOC: http://localhost"
    echo "Open sources:   http://localhost/sources"
    echo "Collector log:  $COLLECTOR_DIR/runtime/collector.log"
    unset ADMIN_PASSWORD SOURCE_SECRET TOKEN
    exit 0
  fi

  sleep 3
done

echo
echo "The collector is running, but the source did not become healthy yet."
echo "Recent collector log:"
tail -n 80 runtime/collector.log || true
echo
echo "Recent API log:"
cd "$ROOT"
docker compose logs --no-color --tail=100 api || true
exit 2
