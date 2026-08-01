# Wazuh Integration

TRUST-SOC uses Wazuh as a telemetry and alert source; it does not replace Wazuh.

1. Run `./scripts/install-wazuh-docker.sh` for the official single-node development stack.
2. Change all Wazuh default credentials.
3. Configure `TRUSTSOC_WAZUH_ENABLED`, `TRUSTSOC_WAZUH_URL`, `TRUSTSOC_WAZUH_USERNAME`, `TRUSTSOC_WAZUH_PASSWORD`, and TLS verification in `.env`.
4. Restart the API and worker.
5. Confirm `/api/integrations/wazuh/health` after authentication.

For real organizations, use Wazuh single-node or multi-node deployment according to scale and availability requirements. Agents should normally be installed directly on endpoints to collect native operating-system telemetry.
