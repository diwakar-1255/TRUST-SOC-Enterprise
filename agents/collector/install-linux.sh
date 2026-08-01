#!/usr/bin/env bash
set -euo pipefail
sudo install -d -m 0750 /opt/trustsoc-collector /opt/trustsoc-collector/runtime /etc/trustsoc
sudo cp -r trust_agent requirements.txt /opt/trustsoc-collector/
sudo python3 -m venv /opt/trustsoc-collector/.venv
sudo /opt/trustsoc-collector/.venv/bin/pip install -r /opt/trustsoc-collector/requirements.txt
sudo install -m 0600 agent.env /etc/trustsoc/agent.env
sudo install -m 0644 packaging/trustsoc-collector.service /etc/systemd/system/trustsoc-collector.service
sudo systemctl daemon-reload
sudo systemctl enable --now trustsoc-collector
sudo systemctl status trustsoc-collector --no-pager
