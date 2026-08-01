import hashlib
import hmac
import json
from datetime import datetime
from typing import Any


def canonical(event: dict[str, Any]) -> bytes:
    selected = {
        "source_id": str(event["source_id"]),
        "sequence": int(event["sequence"]),
        "event_type": event["event_type"],
        "observed_at": event["observed_at"].isoformat()
        if isinstance(event["observed_at"], datetime)
        else event["observed_at"],
        "body": event["body"],
        "previous_hash": event.get("previous_hash"),
    }
    return json.dumps(
        selected, sort_keys=True, separators=(",", ":"), default=str
    ).encode()


def sign_event(event: dict[str, Any], secret: str) -> dict[str, Any]:
    event_hash = hashlib.sha256(canonical(event)).hexdigest()
    signature = hmac.new(
        secret.encode(), event_hash.encode(), hashlib.sha256
    ).hexdigest()
    return {**event, "event_hash": event_hash, "signature": signature}
