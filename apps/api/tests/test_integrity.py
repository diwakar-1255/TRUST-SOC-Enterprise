from datetime import UTC, datetime

from trustsoc.security import compute_event_hash, compute_signature
from trustsoc.services.integrity import verify_event


def test_valid_hash_chain_and_signature():
    event = {
        "source_id": "00000000-0000-0000-0000-000000000001",
        "sequence": 1,
        "event_type": "heartbeat",
        "observed_at": datetime.now(UTC),
        "body": {"status": "ok"},
        "previous_hash": None,
    }
    event["event_hash"] = compute_event_hash(event)
    event["signature"] = compute_signature("secret", event["event_hash"])
    result = verify_event(
        event, secret="secret", expected_previous_hash=None, expected_next_sequence=1
    )
    assert result.valid
