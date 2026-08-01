#!/usr/bin/env bash
set -euo pipefail
base=${TRUSTSOC_URL:-http://localhost/api}
email=${TRUSTSOC_EMAIL:-admin@example.com}
password=${TRUSTSOC_PASSWORD:?Set TRUSTSOC_PASSWORD to the bootstrap admin password}
token=$(curl -fsS "$base/auth/login" -H 'Content-Type: application/json' -d "{\"email\":\"$email\",\"password\":\"$password\"}" | python3 -c 'import json,sys;print(json.load(sys.stdin)["access_token"])')
curl -fsS "$base/sources" -H "Authorization: Bearer $token" -H 'Content-Type: application/json' -d '{"name":"ubuntu-host","source_type":"linux","expected_heartbeat_seconds":60,"expected_fields":["hostname","os","status"]}' | python3 -m json.tool
