#!/usr/bin/env bash
set -Eeuo pipefail

KEY="${HONEYPOT_SSH_KEY:-$HOME/honeypot-vm_key (1).pem}"
REMOTE_USER="${HONEYPOT_SSH_USER:-diwakar_1255}"
REMOTE_HOST="${HONEYPOT_SSH_HOST:-52.237.90.251}"
LOCAL_PORT="${HONEYPOT_LOCAL_PORT:-18000}"

[[ -f "$KEY" ]] || { echo "SSH key not found: $KEY" >&2; exit 1; }
chmod 600 "$KEY"

exec ssh -N -T   -i "$KEY"   -o ExitOnForwardFailure=yes   -o ServerAliveInterval=30   -o ServerAliveCountMax=3   -L "127.0.0.1:${LOCAL_PORT}:127.0.0.1:8000"   "${REMOTE_USER}@${REMOTE_HOST}"
