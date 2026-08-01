#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ -f .env ]] && ! grep -q "CHANGE_ME" .env; then echo "Existing initialized .env preserved."; exit 0; fi
[[ -f .env ]] || cp .env.example .env
python3 - <<'PY'
from pathlib import Path
import secrets,re
p=Path('.env');t=p.read_text()
def replace(name,value):
 global t
 t=re.sub(rf'^{name}=.*$',f'{name}={value}',t,flags=re.M)
replace('TRUSTSOC_JWT_SECRET',secrets.token_urlsafe(48))
replace('TRUSTSOC_ENCRYPTION_KEY',secrets.token_urlsafe(48))
replace('TRUSTSOC_BOOTSTRAP_ADMIN_PASSWORD',secrets.token_urlsafe(24))
db=secrets.token_urlsafe(32)
replace('POSTGRES_PASSWORD',db)
replace('TRUSTSOC_DATABASE_URL',f'postgresql+asyncpg://trustsoc:{db}@postgres:5432/trustsoc')
replace('GRAFANA_ADMIN_PASSWORD',secrets.token_urlsafe(20))
p.write_text(t)
PY
mkdir -p secrets backups
chmod 600 .env
printf '\nBootstrap complete. Credentials are in .env. Do not commit this file.\n'
