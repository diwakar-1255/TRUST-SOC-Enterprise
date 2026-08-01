from datetime import UTC

from trustsoc.models import SourceStatus
from trustsoc.services.wazuh_sync import (
    normalize_alert,
    parse_timestamp,
    severity_from_level,
    source_status,
)


def test_wazuh_severity_mapping():
    assert severity_from_level(15) == "critical"
    assert severity_from_level(12) == "high"
    assert severity_from_level(7) == "medium"
    assert severity_from_level(6) == "low"


def test_wazuh_source_status_mapping():
    assert source_status("active") == (SourceStatus.healthy, 100.0)
    assert source_status("disconnected") == (SourceStatus.critical, 25.0)
    assert source_status("pending") == (SourceStatus.degraded, 70.0)


def test_normalize_wazuh_alert():
    alert = normalize_alert(
        {
            "_index": "wazuh-alerts-4.x-2026.07.19",
            "_id": "abc123",
            "_source": {
                "timestamp": "2026-07-19T15:30:00.000Z",
                "agent": {"id": "001", "name": "DESKTOP", "ip": "10.0.0.4"},
                "manager": {"name": "wazuh.manager"},
                "rule": {
                    "id": "60122",
                    "level": 12,
                    "description": "Windows authentication failure",
                    "groups": ["windows", "authentication_failed"],
                    "mitre": {"id": ["T1110"], "tactic": ["Credential Access"]},
                },
                "decoder": {"name": "windows_eventchannel"},
            },
        }
    )
    assert alert["external_id"].endswith(":abc123")
    assert alert["severity"] == "high"
    assert alert["agent_name"] == "DESKTOP"
    assert alert["mitre_techniques"] == ["T1110"]
    assert alert["event_timestamp"].tzinfo == UTC


def test_parse_timestamp_falls_back_to_utc():
    assert parse_timestamp(None).tzinfo == UTC
