# Deployed Honeypot SOC Integration

This connector imports real SSH, HTTP, HTTPS and FTP attack intelligence from the deployed honeypot SOC into TRUST-SOC.

## Security architecture

The honeypot API remains bound to `127.0.0.1:8000` on the Azure VM. TRUST-SOC connects through an encrypted SSH local forward on port `18000`; the API is not exposed publicly.

## Data imported

- Current event, attacker and alert totals
- Service-level activity counts
- Critical, high and medium alert counts
- Recent normalized honeypot events
- High-risk attacker profiles
- Open SOC alerts and MITRE technique identifiers

Passwords or captured secrets are not imported by this connector.

## Required tunnel

```bash
cd /mnt/a/TRUST-SOC-Enterprise
./scripts/honeypot-tunnel.sh
```

Keep it running, or install the optional user service:

```bash
./scripts/install-honeypot-tunnel-service.sh /mnt/a/TRUST-SOC-Enterprise
```

## URLs

- TRUST-SOC Honeypot Intelligence: `http://localhost/honeypot`
- Integration status: `http://localhost/integrations`
- Deployed Grafana: `https://52.237.90.251/grafana/`
