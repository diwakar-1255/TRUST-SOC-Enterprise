# Wazuh Real-Time Portal Upgrade

This upgrade adds a real-time customer security portal to TRUST-SOC.

## Data flow

1. TRUST-SOC authenticates to the Wazuh Manager API.
2. Wazuh agents are synchronized into tenant-scoped protected assets and telemetry sources.
3. TRUST-SOC queries the Wazuh Indexer over authenticated HTTPS.
4. Alerts are normalized, deduplicated, severity-classified, and stored in PostgreSQL.
5. The portal refreshes every 15 seconds and the API synchronization loop runs every 60 seconds.

## New API endpoints

- `GET /portal/summary`
- `GET /portal/alerts`
- `GET /portal/assets`
- `GET /integrations/wazuh/status`
- `POST /integrations/wazuh/sync`

## New portal pages

- `/` — real-time security overview
- `/alerts` — normalized Wazuh alert feed
- `/assets` — protected asset inventory
- `/integrations` — Wazuh health and manual synchronization

## Security boundaries

The lab configuration uses self-signed Wazuh certificates and disables TLS verification. Production must use trusted certificates, tenant-specific integration credentials, secret management, least-privilege indexer accounts, and network restrictions around ports 55000 and 9200.

The synchronization service is tenant-scoped in the database. The current global environment variables connect one Wazuh deployment to the bootstrap organization. A multi-customer deployment should move integration credentials into a per-tenant secret store.
