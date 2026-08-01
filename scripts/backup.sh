#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/..";set -a;source .env;set +a
stamp=$(date -u +%Y%m%dT%H%M%SZ);mkdir -p backups
docker compose exec -T postgres pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" --format=custom > "backups/trustsoc-$stamp.dump"
sha256sum "backups/trustsoc-$stamp.dump" > "backups/trustsoc-$stamp.dump.sha256"
echo "Created backups/trustsoc-$stamp.dump"
