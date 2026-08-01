# Security Policy

Report suspected vulnerabilities privately to the project security owner. Do not include credentials, customer logs, exploit payloads, or personal data in public issues.

## Security assumptions

- Production secrets are stored in a dedicated secret manager, not `.env` files.
- External TLS terminates at an approved reverse proxy or load balancer.
- Collector identities are unique, revocable, and rotated.
- All simulation targets are explicitly allowlisted and authorized.
- Recovery actions use least-privileged service accounts and approval workflows.
- Raw telemetry retention follows legal, privacy, and organizational policies.

## Supported branch

The latest tagged release is the supported line. Security fixes should be backported according to organizational policy.
