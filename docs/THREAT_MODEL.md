# Threat Model

## Protected assets

Telemetry authenticity, event order, event completeness, detection dependencies, administrator actions, organization boundaries, source identities, secrets, evidence timelines, and recovery approvals.

## Principal threats

- Collector impersonation or credential theft.
- Replay, deletion, duplication, reordering, timestamp manipulation, and field poisoning.
- Compromised parser or integration adapter.
- Tenant-boundary bypass.
- Privilege escalation or unauthorized simulation.
- Audit-log alteration.
- Denial of service through telemetry flooding.
- Dependency outage causing silent blindness.
- Malicious recovery automation.

## Implemented mitigations

HMAC signatures, hash chaining, sequence validation, unique database constraints, encrypted source secrets, Argon2 password hashing, short-lived access tokens, refresh-token versioning, RBAC, audit events, request identifiers, rate limiting at the gateway, container non-root users, read-only filesystems, health checks, safe synthetic simulations, and recommendation-first recovery.

## Required production mitigations

OIDC/MFA, mTLS enrollment, certificate revocation, external KMS/HSM, immutable audit export, WAF/API gateway, SIEM monitoring of TRUST-SOC itself, DDoS protection, tested disaster recovery, endpoint binary signing, SBOM and provenance, independent penetration test, privacy impact assessment, data retention controls, and formal approval workflows.
