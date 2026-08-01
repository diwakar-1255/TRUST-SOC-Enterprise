#!/usr/bin/env bash
set -Eeuo pipefail

WAZUH_DIR="${1:-/mnt/a/TRUST-SOC-Enterprise/vendor/wazuh-docker/single-node}"
PUBLIC_DOCKER_CONFIG="${HOME}/.docker-wazuh-public"

fail() {
  echo "ERROR: $*" >&2
  exit 1
}

cd "$WAZUH_DIR" || fail "Wazuh directory not found: $WAZUH_DIR"

if [[ ! -f docker-compose.yml && ! -f compose.yaml && ! -f compose.yml ]]; then
  fail "No Docker Compose file found in $WAZUH_DIR"
fi

if [[ ! -f config/wazuh_indexer_ssl_certs/root-ca.pem ]]; then
  fail "Wazuh certificates are missing. Certificate generation must complete first."
fi

mkdir -p "$PUBLIC_DOCKER_CONFIG"
cat > "${PUBLIC_DOCKER_CONFIG}/config.json" <<'EOF'
{
  "auths": {}
}
EOF
chmod 700 "$PUBLIC_DOCKER_CONFIG"
chmod 600 "${PUBLIC_DOCKER_CONFIG}/config.json"

unset DOCKER_AUTH_CONFIG || true

echo "Testing Docker daemon with the isolated public-registry configuration..."
docker --config "$PUBLIC_DOCKER_CONFIG" info >/dev/null

mapfile -t IMAGES < <(
  docker --config "$PUBLIC_DOCKER_CONFIG" compose config --images |
  sed '/^[[:space:]]*$/d' |
  sort -u
)

if [[ "${#IMAGES[@]}" -eq 0 ]]; then
  fail "No images were found in the Wazuh Compose configuration."
fi

echo
echo "Wazuh images to download:"
printf '  %s\n' "${IMAGES[@]}"

for image in "${IMAGES[@]}"; do
  echo
  echo "Pulling $image"
  pulled=false
  for attempt in 1 2 3 4 5; do
    echo "Attempt $attempt of 5..."
    if docker --config "$PUBLIC_DOCKER_CONFIG" pull "$image"; then
      pulled=true
      break
    fi
    sleep $((attempt * 10))
  done

  if [[ "$pulled" != true ]]; then
    fail "Could not download $image after five attempts."
  fi
done

echo
echo "Starting Wazuh without additional image pulls..."
docker --config "$PUBLIC_DOCKER_CONFIG" compose up -d --pull never

echo
echo "Current Wazuh status:"
docker --config "$PUBLIC_DOCKER_CONFIG" compose ps -a

echo
echo "Wazuh images were downloaded using an isolated Docker configuration."
echo "Normal Docker credentials in ~/.docker/config.json were not modified."
