from collections import defaultdict
from typing import Any

SOURCE_CONFIDENCE = {
    "windows_event": 0.95,
    "sysmon": 0.95,
    "auditd": 0.94,
    "wazuh": 0.92,
    "firewall": 0.85,
    "zeek": 0.88,
    "dns": 0.80,
    "suricata": 0.88,
}


def reconstruct(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Create a transparent timeline; no inferred event is labelled observed."""
    timeline = []
    groups: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for event in events:
        key = (str(event.get("body", {}).get("correlation_id", "")), event["event_type"])
        groups[key].append(event)

    for (_, event_type), group in groups.items():
        group.sort(key=lambda item: item["observed_at"])
        sources = {item.get("source_type", "unknown") for item in group}
        classifications = {item.get("classification", "observed") for item in group}
        if "observed" in classifications and len(sources) > 1:
            classification = "corroborated"
        elif "observed" in classifications:
            classification = "observed"
        else:
            classification = "reconstructed"
        confidence = 1.0
        for source in sources:
            confidence *= 1 - SOURCE_CONFIDENCE.get(source, 0.60)
        confidence = round(1 - confidence, 2)
        timeline.append(
            {
                "timestamp": min(item["observed_at"] for item in group),
                "event_type": event_type,
                "classification": classification,
                "confidence": confidence,
                "evidence_ids": [item["id"] for item in group],
                "summary": (
                    f"{event_type} supported by {len(group)} event(s) "
                    f"from {', '.join(sorted(sources))}"
                ),
            }
        )
    return sorted(timeline, key=lambda item: item["timestamp"])
