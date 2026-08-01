from datetime import UTC, datetime
from types import SimpleNamespace

from trustsoc.services.alert_operations import (
    aggregation_window,
    calculate_risk,
    policy_matches,
    priority_for_severity,
)


def test_aggregation_window_rounds_to_fifteen_minutes():
    start, end = aggregation_window(datetime(2026, 7, 20, 10, 29, 33, tzinfo=UTC), 15)
    assert start == datetime(2026, 7, 20, 10, 15, tzinfo=UTC)
    assert end == datetime(2026, 7, 20, 10, 30, tzinfo=UTC)


def test_risk_increases_with_severity_and_repetition():
    low = calculate_risk("low", 3, 1, False)
    medium = calculate_risk("medium", 9, 1, False)
    repeated = calculate_risk("medium", 9, 32, True)
    assert low < medium < repeated <= 100


def test_noise_policy_matches_rule_and_agent_pattern():
    policy = SimpleNamespace(
        enabled=True,
        expires_at=None,
        match_rule_ids=["60608"],
        match_severities=["low"],
        match_groups=["windows_application"],
        match_agent_pattern="DESKTOP-*",
        match_title_pattern="*summary event*",
    )
    alert = SimpleNamespace(
        rule_id="60608",
        severity="low",
        groups=["windows", "windows_application"],
        agent_name="DESKTOP-RPJF0NM",
        title="Summary event of the report's signatures.",
    )
    assert policy_matches(policy, alert)


def test_priority_mapping():
    assert priority_for_severity("critical") == "P1"
    assert priority_for_severity("high") == "P2"
    assert priority_for_severity("low") == "P4"
