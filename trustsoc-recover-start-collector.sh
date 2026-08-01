#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="${1:-$(pwd)}"
cd "$ROOT"

fail() {
  echo "ERROR: $*" >&2
  exit 1
}

[[ -f compose.yaml ]] || fail "Run this from the TRUST-SOC-Enterprise directory."
[[ -d agents/collector/trust_agent ]] || fail "Collector source directory is missing."
docker inspect trust-soc-api-1 >/dev/null 2>&1 || fail "TRUST-SOC API container is not running."
curl -fsS http://localhost/api/health/live >/dev/null || fail "TRUST-SOC API health endpoint is unavailable."

COLLECTOR_DIR="$ROOT/agents/collector"
AGENT_ENV="$COLLECTOR_DIR/agent.env"
SOURCE_NAME="${TRUSTSOC_SOURCE_NAME:-$(hostname)-linux-collector}"

valid_env=false
if [[ -f "$AGENT_ENV" ]]; then
  source_id="$(grep '^TRUSTSOC_AGENT_SOURCE_ID=' "$AGENT_ENV" | cut -d= -f2- || true)"
  source_secret="$(grep '^TRUSTSOC_AGENT_SHARED_SECRET=' "$AGENT_ENV" | cut -d= -f2- || true)"

  if [[ -n "$source_id" && -n "$source_secret" &&
        "$source_id" != "REPLACE_WITH_SOURCE_UUID" &&
        "$source_secret" != "REPLACE_WITH_ONE_TIME_SECRET" ]]; then
    valid_env=true
  fi
fi

if [[ "$valid_env" != true ]]; then
  echo "Collector secret is missing. Rotating the existing source secret safely..."

  rotation="$(
    docker exec -i \
      -e TRUSTSOC_RECOVERY_SOURCE_NAME="$SOURCE_NAME" \
      trust-soc-api-1 python - <<'PY'
import asyncio
import json
import os

from sqlalchemy import select

from trustsoc.database import SessionLocal
from trustsoc.models import SourceStatus, TelemetrySource
from trustsoc.security import encrypt_secret, generate_shared_secret


async def main() -> None:
    source_name = os.environ["TRUSTSOC_RECOVERY_SOURCE_NAME"]

    async with SessionLocal() as db:
        source = await db.scalar(
            select(TelemetrySource).where(TelemetrySource.name == source_name)
        )

        if source is None:
            raise SystemExit(
                f"Telemetry source not found: {source_name}. "
                "Confirm its name on the TRUST-SOC Telemetry Sources page."
            )

        secret = generate_shared_secret()
        source.encrypted_shared_secret = encrypt_secret(secret)
        source.last_sequence = 0
        source.last_event_hash = None
        source.last_heartbeat_at = None
        source.status = SourceStatus.unknown
        source.trust_score = 0

        await db.commit()

        print(json.dumps({
            "source_id": str(source.id),
            "shared_secret": secret,
        }))


asyncio.run(main())
PY
  )" || fail "Could not rotate the source secret."

  source_id="$(
    printf '%s\n' "$rotation" |
      tail -n 1 |
      python3 -c 'import json,sys; print(json.load(sys.stdin)["source_id"])'
  )"

  source_secret="$(
    printf '%s\n' "$rotation" |
      tail -n 1 |
      python3 -c 'import json,sys; print(json.load(sys.stdin)["shared_secret"])'
  )"

  mkdir -p "$COLLECTOR_DIR/runtime"

  cat > "$AGENT_ENV" <<EOF
TRUSTSOC_AGENT_API_URL=http://localhost/api
TRUSTSOC_AGENT_SOURCE_ID=$source_id
TRUSTSOC_AGENT_SHARED_SECRET=$source_secret
TRUSTSOC_AGENT_SOURCE_TYPE=linux
TRUSTSOC_AGENT_HEARTBEAT_SECONDS=30
TRUSTSOC_AGENT_VERIFY_TLS=false
TRUSTSOC_AGENT_SPOOL_PATH=./runtime/spool.jsonl
TRUSTSOC_AGENT_STATE_PATH=./runtime/state.json
EOF

  chmod 600 "$AGENT_ENV"
  unset source_secret
  echo "Collector configuration recovered for source: $SOURCE_NAME"
else
  echo "Existing collector configuration found."
fi

cd "$COLLECTOR_DIR"
mkdir -p runtime

if [[ ! -x .venv/bin/python ]]; then
  echo "Creating Python virtual environment..."
  python3 -m venv .venv
fi

echo "Installing collector dependencies..."
.venv/bin/python -m pip install --disable-pip-version-check -q --upgrade pip
.venv/bin/python -m pip install --disable-pip-version-check -q -r requirements.txt

if [[ -f runtime/collector.pid ]]; then
  old_pid="$(cat runtime/collector.pid || true)"
  if [[ -n "$old_pid" ]] && kill -0 "$old_pid" 2>/dev/null; then
    echo "Stopping previous collector process: $old_pid"
    kill "$old_pid"
    sleep 2
  fi
fi

rm -f runtime/collector.log

nohup .venv/bin/python -m trust_agent.main \
  > runtime/collector.log 2>&1 &

collector_pid=$!
echo "$collector_pid" > runtime/collector.pid

sleep 3

if ! kill -0 "$collector_pid" 2>/dev/null; then
  echo "Collector exited during startup."
  cat runtime/collector.log || true
  exit 2
fi

source_id="$(grep '^TRUSTSOC_AGENT_SOURCE_ID=' agent.env | cut -d= -f2-)"

echo "Collector started with PID $collector_pid."
echo "Waiting for a verified heartbeat..."

for attempt in $(seq 1 15); do
  source_state="$(
    docker exec -i \
      -e TRUSTSOC_RECOVERY_SOURCE_ID="$source_id" \
      trust-soc-api-1 python - <<'PY'
import asyncio
import json
import os
import uuid

from sqlalchemy import select

from trustsoc.database import SessionLocal
from trustsoc.models import TelemetrySource


async def main() -> None:
    source_id = uuid.UUID(os.environ["TRUSTSOC_RECOVERY_SOURCE_ID"])

    async with SessionLocal() as db:
        source = await db.scalar(
            select(TelemetrySource).where(TelemetrySource.id == source_id)
        )

        if source is None:
            print(json.dumps({"found": False}))
            return

        print(json.dumps({
            "found": True,
            "status": source.status.value,
            "trust_score": source.trust_score,
            "last_heartbeat_at": (
                source.last_heartbeat_at.isoformat()
                if source.last_heartbeat_at
                else None
            ),
            "last_sequence": source.last_sequence,
        }))


asyncio.run(main())
PY
  )"

  status="$(
    printf '%s\n' "$source_state" |
      tail -n 1 |
      python3 -c 'import json,sys; print(json.load(sys.stdin).get("status", "missing"))'
  )"

  heartbeat="$(
    printf '%s\n' "$source_state" |
      tail -n 1 |
      python3 -c 'import json,sys; print(json.load(sys.stdin).get("last_heartbeat_at") or "")'
  )"

  echo "Attempt $attempt: status=$status heartbeat=${heartbeat:-none}"

  if [[ "$status" == "healthy" && -n "$heartbeat" ]]; then
    echo
    echo "Collector recovery succeeded."
    printf '%s\n' "$source_state" | tail -n 1 | python3 -m json.tool
    echo
    echo "Refresh: http://localhost"
    exit 0
  fi

  sleep 4
done

echo
echo "Collector is running, but no healthy heartbeat was recorded."
echo "Collector process:"
ps -p "$collector_pid" -f || true
echo
echo "Runtime files:"
ls -lah runtime || true
echo
echo "Spool preview:"
tail -n 3 runtime/spool.jsonl 2>/dev/null || true
echo
echo "Recent API logs:"
cd "$ROOT"
docker compose logs --no-color --tail=120 api || true
exit 3
