# TRUST-SOC Build and Validation Report

Generated: 2026-07-17

## Delivered scope

- FastAPI control plane with multi-tenant data model, JWT authentication, RBAC, audit events, PostgreSQL, Redis/Celery, signed telemetry ingestion, replay detection, hash-chain verification, trust scoring, rule dependencies, Detection Blindness Map, evidence reconstruction, authorized simulation workflows, and Wazuh API integration.
- Next.js SOC dashboard with overview, telemetry-source, blindness, detection-rule, and validation-run views.
- Cross-platform signed collector with durable local spool, Linux systemd installation, and Windows scheduled-task installation.
- Docker Compose stack for API, worker, scheduler, web, PostgreSQL, Redis, Nginx, OpenTelemetry Collector, Prometheus, and Grafana.
- Official Wazuh Docker bootstrap integration, Alembic schema migrations, backup/restore scripts, CI/CD, Helm deployment path, threat model, operations guide, and production-readiness gate.

## Validation completed

- Python compilation: passed.
- Shell syntax: passed.
- JSON and non-templated YAML parsing: passed.
- Ruff linting and formatting: passed.
- Backend unit tests: **5 passed**.
- FastAPI import and OpenAPI generation: passed; 14 API paths generated during validation.
- Alembic offline schema generation: passed; 193 lines of PostgreSQL DDL generated.
- Frontend TypeScript check: passed.
- Next.js production build: passed; 8 static routes generated including framework fallback route.
- NPM audit: **0 vulnerabilities** for the locked dependency tree at validation time.
- Bootstrap secret generation: passed for JWT, encryption, administrator, PostgreSQL, database URL, and Grafana credentials.
- Secret-pattern scan: passed.

## Environment limitation

The generation environment did not expose a Docker daemon or Docker Compose binary, so containers were not started here. Run `./scripts/dev-up.sh` on the target Ubuntu/Docker Desktop system and complete the organization-specific controls in `docs/PRODUCTION_READINESS.md` before any production deployment.

## Repository size

- Source/configuration files: 120
- Approximate text lines: 9047
