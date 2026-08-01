#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
echo "[1/6] Python syntax"
python3 -m compileall -q apps/api/trustsoc apps/api/tests agents/collector/trust_agent
echo "[2/6] Shell syntax"
find scripts agents -type f -name '*.sh' -print0 | xargs -0 -r -n1 bash -n
echo "[3/6] JSON syntax"
python3 - <<'PYJSON'
import json
from pathlib import Path
for p in Path('.').rglob('*.json'):
 if 'node_modules' in p.parts or '.next' in p.parts: continue
 json.loads(p.read_text())
print('JSON OK')
PYJSON
echo "[4/6] YAML parse (when PyYAML is available)"
python3 - <<'PYYAML'
try:
 import yaml
except Exception:
 print('PyYAML not installed; YAML parse skipped')
else:
 from pathlib import Path
 for p in list(Path('.').rglob('*.yml'))+list(Path('.').rglob('*.yaml')):
  if 'helm/trust-soc/templates' in p.as_posix(): continue
  with p.open() as f: list(yaml.safe_load_all(f))
 print('YAML OK')
PYYAML
echo "[5/6] Docker Compose schema"
if command -v docker >/dev/null 2>&1; then docker compose --env-file .env.example config >/dev/null; else echo 'Docker unavailable; compose validation skipped'; fi
echo "[6/6] Secret scan patterns"
if grep -RInE --exclude-dir=node_modules --exclude-dir=.next '(AKIA[0-9A-Z]{16}|BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY)' --exclude-dir=.git .; then echo 'Potential secret found' >&2; exit 1; fi
echo "Validation complete"
