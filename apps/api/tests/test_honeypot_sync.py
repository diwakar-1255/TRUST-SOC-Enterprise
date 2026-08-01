from trustsoc.services.honeypot_sync import _groups, _mitre, _rule_level, _severity


def test_honeypot_severity_mapping():
    assert _severity("Critical") == "critical"
    assert _severity("unexpected") == "low"
    assert _rule_level("critical") == 15
    assert _rule_level("high") == 12


def test_honeypot_mitre_and_groups():
    item = {
        "service": "HTTP",
        "event_type": "Suspicious Web Request",
        "attack_type": "Remote Code Execution Attempt",
        "mitre_technique": "T1059 - Command and Scripting Interpreter",
    }
    assert _mitre(item) == ["T1059"]
    assert _groups(item) == [
        "honeypot",
        "http",
        "suspicious_web_request",
        "remote_code_execution_attempt",
    ]
