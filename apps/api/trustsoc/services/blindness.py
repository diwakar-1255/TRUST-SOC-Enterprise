from collections.abc import Iterable
from typing import Any

SEVERITY_WEIGHT = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def build_blindness_finding(
    *,
    source: dict[str, Any],
    rules: Iterable[dict[str, Any]],
    assets: Iterable[dict[str, Any]],
    total_enabled_rules: int,
) -> dict[str, Any]:
    affected = []
    techniques: set[str] = set()
    highest = 1
    for rule in rules:
        source_match = source["source_type"] in rule.get("source_types", [])
        missing_fields = sorted(
            set(rule.get("required_fields", [])) - set(source.get("available_fields", []))
        )
        unavailable = source.get("status") in {"critical", "unknown"}
        if source_match and (unavailable or missing_fields):
            row = {
                **rule,
                "missing_fields": missing_fields,
                "reason": "source_unavailable" if unavailable else "required_fields_missing",
            }
            affected.append(row)
            techniques.update(rule.get("mitre_techniques", []))
            highest = max(highest, SEVERITY_WEIGHT.get(rule.get("severity", "medium"), 2))

    affected_asset_types = {t for rule in affected for t in rule.get("protected_asset_types", [])}
    affected_assets = [asset for asset in assets if asset.get("asset_type") in affected_asset_types]
    if affected_assets:
        highest = max(highest, max(min(int(a.get("criticality", 1)), 4) for a in affected_assets))
    severity = {1: "low", 2: "medium", 3: "high", 4: "critical"}[highest]
    loss = round((len(affected) / max(total_enabled_rules, 1)) * 100, 2)
    return {
        "source_id": source["id"],
        "source_name": source["name"],
        "source_status": source["status"],
        "affected_rules": affected,
        "affected_techniques": sorted(techniques),
        "affected_assets": affected_assets,
        "coverage_loss_percent": loss,
        "severity": severity,
    }
