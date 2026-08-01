# TRUST-SOC Incident and Noise-Reduction Upgrade

## Purpose

The upgrade converts raw Wazuh alert streams into a manageable SOC workflow while preserving every original alert. Repeated events are grouped into bounded time windows, assigned a risk score, and escalated to incidents when policy thresholds are met.

## Data flow

```text
Wazuh raw alert
  -> immutable SecurityAlert
  -> noise-policy evaluation
  -> correlated AlertGroup
  -> risk score
  -> analyst workflow or automatic incident
  -> SecurityIncident with SLA and response state
```

## Evidence preservation

Suppression does not delete alerts. Raw records remain in `security_alerts`, retain their Wazuh external ID and event data, and stay accessible from the alert-group detail page. Suppression changes workflow visibility, not evidentiary storage.

## Default correlation

The default aggregation window is 15 minutes. The fingerprint contains the integration, endpoint identity, Wazuh rule ID, and window start. This prevents unrelated events from being merged while reducing repeated alerts such as Wazuh rule 60608.

## Automatic incidents

By default, an incident is generated when:

- Wazuh rule level is 12 or higher; or
- A medium, high, or critical group reaches 10 occurrences within the aggregation window.

The thresholds are configurable through `.env`.

## Production boundaries

Before production use, configure SSO/MFA, per-tenant authorization tests, a distributed synchronization lock for multi-replica API deployments, trusted TLS, external secrets management, retention policy, analyst on-call schedules, notification integrations, and independent penetration testing.
