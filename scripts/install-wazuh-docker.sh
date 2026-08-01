#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
version=${WAZUH_DOCKER_VERSION:-v4.14.6}
mkdir -p vendor
if [[ ! -d vendor/wazuh-docker/.git ]]; then git clone --depth 1 --branch "$version" https://github.com/wazuh/wazuh-docker.git vendor/wazuh-docker; fi
cd vendor/wazuh-docker/single-node
if command -v sysctl >/dev/null 2>&1; then sudo sysctl -w vm.max_map_count=262144 || true; fi
docker compose -f generate-indexer-certs.yml run --rm generator
docker compose up -d
printf '\nWazuh stack started. Dashboard: https://localhost\nChange all official default credentials, then configure WAZUH_* values in TRUST-SOC .env.\n'
docker compose ps
