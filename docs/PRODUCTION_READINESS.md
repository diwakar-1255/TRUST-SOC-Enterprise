# Production Readiness Gate

Do not present a successful local startup as production certification. A real organization must approve all gates below.

## Mandatory before production

- [ ] Named system owner, data owner, security owner, and incident-response owner.
- [ ] Asset inventory, data classification, privacy review, and retention schedule.
- [ ] OIDC/SAML integration with MFA and break-glass controls.
- [ ] Production TLS certificates and collector mTLS enrollment.
- [ ] Secrets moved from `.env` to Vault, Azure Key Vault, AWS Secrets Manager/KMS, or equivalent.
- [ ] PostgreSQL high availability, encryption, least privilege, backup encryption, and successful restore drill.
- [ ] Wazuh production topology sized for endpoint count and event throughput.
- [ ] Capacity and soak testing using representative event rates.
- [ ] External penetration test and remediation verification.
- [ ] Dependency, container, IaC, and secret scans enforced in CI/CD.
- [ ] Signed release artifacts, SBOM, provenance, and rollback procedure.
- [ ] Collector package signing and tamper-protection review.
- [ ] Network segmentation, firewall policy, egress restrictions, and monitoring.
- [ ] Simulation allowlists, change tickets, maintenance windows, and rollback plans.
- [ ] Recovery actions remain approval-gated until individually validated.
- [ ] Alert routing, escalation paths, on-call ownership, and runbooks tested.
- [ ] Legal authorization for telemetry collection and defensive simulations.
- [ ] Disaster-recovery RTO/RPO approved and exercised.

## Release evidence

Every production release should include test results, threat-model changes, migration plan, rollback plan, SBOM, vulnerability scan, signed images, change approval, and operator runbook updates.
