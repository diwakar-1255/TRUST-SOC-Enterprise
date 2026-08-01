#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/..";set -a;source .env;set +a
file=${1:-};[[ -n "$file" && -f "$file" ]] || { echo "Usage: $0 backups/file.dump"; exit 2; }
[[ -f "$file.sha256" ]] && sha256sum -c "$file.sha256"
read -r -p "Restore $file into $POSTGRES_DB? Type RESTORE: " answer;[[ "$answer" == RESTORE ]] || exit 1
docker compose exec -T postgres pg_restore -U "$POSTGRES_USER" -d "$POSTGRES_DB" --clean --if-exists < "$file"
