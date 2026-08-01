# API Examples

## Login

```bash
curl -s http://localhost/api/auth/login -H 'Content-Type: application/json' -d '{"email":"admin@example.com","password":"PASSWORD_FROM_ENV"}'
```

## Create an asset

```bash
curl -s http://localhost/api/assets -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d '{"hostname":"dc01.example.local","asset_type":"domain_controller","operating_system":"Windows Server 2022","criticality":5}'
```

## Create a source

```bash
curl -s http://localhost/api/sources -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d '{"name":"dc01-sysmon","source_type":"sysmon","expected_heartbeat_seconds":60,"expected_fields":["process_name","command_line","user"]}'
```

Save the one-time source secret in an approved secret store and configure the collector.
