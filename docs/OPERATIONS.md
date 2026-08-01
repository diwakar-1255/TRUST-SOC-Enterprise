# Operations

## Daily

Review critical telemetry sources, trust-score changes, canary failures, integrity failures, queue depth, storage growth, authentication anomalies, and Wazuh integration health.

## Weekly

Run approved synthetic validation scenarios, test one backup restore in a non-production environment, review new rules and field dependencies, rotate expiring certificates, and close stale privileged accounts.

## Incident: telemetry source becomes critical

1. Confirm the source and affected asset.
2. Review the Detection Blindness Map before changing the source.
3. Preserve local evidence and network evidence.
4. Confirm whether the failure is sensor, agent, network, parser, schema, rule, integrity, time, or response related.
5. Use an approved recovery action.
6. Send a signed canary event.
7. Verify collection, parsing, rule execution, alert generation, and trust-score recovery.
8. Record the full timeline and lessons learned.
