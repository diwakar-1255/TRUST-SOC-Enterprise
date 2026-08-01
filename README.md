# TRUST-SOC Enterprise

**Tamper-Resilient Unified Security Telemetry and SOC Validation Platform**

TRUST-SOC validates whether an organization's monitoring pipeline can still be trusted when telemetry is interrupted, delayed, duplicated, altered, cleared, redirected, or parsed incorrectly. It combines telemetry integrity, detection engineering, evidence reconstruction, and defensive validation.

## Implemented runnable foundation

- Multi-tenant FastAPI API with JWT authentication, RBAC, audit events, health endpoints, and Prometheus metrics.
- PostgreSQL persistence and Redis-backed task processing.
- Asset and telemetry-source inventory.
- Signed telemetry ingestion using sequence numbers, HMAC verification, hash chaining, replay detection, duplicate detection, and field completeness checks.
- Heartbeat and canary processing.
- Telemetry Trust Score calculation.
- Detection-rule inventory and source/field dependency analysis.
- Detection Blindness Map API.
- Evidence Reconstruction Engine with explicit observed/corroborated/inferred classifications.
- Safe simulation orchestration for telemetry gaps, delay, duplication, schema drift, and event loss.
- Next.js SOC dashboard.
- OpenTelemetry Collector, Prometheus, Grafana, and Nginx gateway.
- Host collector with local encrypted spool and Linux/Windows launch helpers.
- Wazuh API adapter and official Wazuh Docker bootstrap script.
- Docker Compose, CI/CD, tests, backup/restore scripts, Helm chart, threat model, and production-readiness checklist.

## Important production boundary

This repository is an enterprise-oriented, deployable engineering foundation. It is **not automatically safe for direct production rollout without organization-specific validation**. Before protecting a real organization, complete the controls in `docs/PRODUCTION_READINESS.md`, including external penetration testing, key management, TLS certificates, high availability, capacity testing, backup restoration tests, endpoint-agent signing, legal approval, and incident-response integration.

## Quick start

Requirements: Docker Desktop/Engine with Compose v2, Git, 8–12 GB RAM available to Docker for the core stack. Running Wazuh alongside it commonly requires 20 GB or more, depending on topology and retention.

```bash
cp .env.example .env
./scripts/bootstrap.sh
./scripts/dev-up.sh
```

Open:

- TRUST-SOC: `http://localhost`
- API documentation: `http://localhost/api/docs`
- Grafana: `http://localhost:3001`
- Prometheus: `http://localhost:9090`

The bootstrap administrator credentials are written to `.env`. Change them after first login.

## Validate the repository

```bash
./scripts/validate.sh
```

## Start Wazuh in Docker

```bash
./scripts/install-wazuh-docker.sh
```

Then set `TRUSTSOC_WAZUH_ENABLED=true` and the correct Wazuh API credentials in `.env`, and restart the API and worker:

```bash
docker compose up -d --force-recreate api worker
```

## Repository map

```text
apps/api              FastAPI control plane and analysis engines
apps/web              Next.js SOC dashboard
agents/collector      Cross-platform signed telemetry collector
infra/nginx           Reverse proxy and security headers
infra/otel            OpenTelemetry Collector configuration
infra/prometheus      Metrics scraping configuration
infra/grafana         Grafana provisioning
helm/trust-soc        Kubernetes/Helm deployment path
scripts               Bootstrap, lifecycle, validation, backup and Wazuh scripts
docs                  Architecture, threat model, operations and readiness
```

## Security model

TRUST-SOC does not execute uncontrolled destructive attacks. Simulation modules create authorized, synthetic telemetry impairment experiments. Recovery automation is recommendation-first and requires approval by design.

## Real-time Wazuh customer portal

Version 0.2 adds continuous Wazuh agent and alert synchronization, tenant-scoped security alert storage, live severity counters, MITRE ATT&CK activity, protected asset inventory, integration health, automatic access-token renewal, and customer portal pages for alerts and assets.

See `docs/WAZUH_PORTAL_UPGRADE.md` for the data flow and production security boundaries.

## Alert correlation and incident response

Version 0.3 adds an enterprise SOC operations layer:

- Fifteen-minute alert aggregation by integration, endpoint, and rule.
- Risk scoring based on severity, Wazuh level, repetition, MITRE mapping, and asset criticality.
- Analyst acknowledgement, investigation, suppression, and resolution workflows.
- Automatic incident creation for level 12+ Wazuh detections or repeated medium/high detections.
- Incident priority, SLA deadlines, containment and resolution states.
- Noise policies that preserve raw evidence while suppressing or downgrading known benign patterns.
- Tenant-scoped audit records for alert, incident, and noise-policy actions.

Portal routes:

- Correlated queue: `http://localhost/alerts`
- Incidents: `http://localhost/incidents`
- Noise policies: `http://localhost/noise-rules`
