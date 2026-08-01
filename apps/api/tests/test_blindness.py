from trustsoc.services.blindness import build_blindness_finding


def test_blindness_finding_maps_rule_and_technique():
    result = build_blindness_finding(
        source={
            "id": "s1",
            "name": "Sysmon",
            "source_type": "sysmon",
            "status": "critical",
            "available_fields": [],
        },
        rules=[
            {
                "id": "r1",
                "name": "PowerShell",
                "severity": "high",
                "source_types": ["sysmon"],
                "required_fields": ["command_line"],
                "mitre_techniques": ["T1059.001"],
                "protected_asset_types": ["endpoint"],
            }
        ],
        assets=[{"id": "a1", "hostname": "host1", "asset_type": "endpoint", "criticality": 4}],
        total_enabled_rules=1,
    )
    assert result["coverage_loss_percent"] == 100
    assert result["severity"] == "critical"
    assert result["affected_techniques"] == ["T1059.001"]
