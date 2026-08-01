from datetime import UTC, datetime
from uuid import uuid4

from trustsoc.services.reconstruction import reconstruct


def test_multiple_sources_are_corroborated():
    now = datetime.now(UTC)
    events = [
        {
            "id": uuid4(),
            "event_type": "network_connection",
            "observed_at": now,
            "body": {"correlation_id": "x"},
            "classification": "observed",
            "source_type": "zeek",
        },
        {
            "id": uuid4(),
            "event_type": "network_connection",
            "observed_at": now,
            "body": {"correlation_id": "x"},
            "classification": "observed",
            "source_type": "firewall",
        },
    ]
    timeline = reconstruct(events)
    assert timeline[0]["classification"] == "corroborated"
    assert timeline[0]["confidence"] > 0.9
