#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="${1:-/mnt/a/TRUST-SOC-Enterprise}"
SCRIPT="$ROOT/scripts/honeypot-tunnel.sh"
[[ -x "$SCRIPT" ]] || { echo "Tunnel script not found: $SCRIPT" >&2; exit 1; }

mkdir -p "$HOME/.config/systemd/user"
cat > "$HOME/.config/systemd/user/trustsoc-honeypot-tunnel.service" <<EOF
[Unit]
Description=TRUST-SOC encrypted honeypot API tunnel
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$SCRIPT
Restart=always
RestartSec=10

[Install]
WantedBy=default.target
EOF

systemctl --user daemon-reload
systemctl --user enable --now trustsoc-honeypot-tunnel.service
loginctl enable-linger "$USER" 2>/dev/null || true
systemctl --user status trustsoc-honeypot-tunnel.service --no-pager
