from dataclasses import dataclass
from typing import Any

from trustsoc.security import compute_event_hash, verify_signature


@dataclass(frozen=True)
class IntegrityResult:
    hash_valid: bool
    signature_valid: bool
    chain_valid: bool
    sequence_valid: bool

    @property
    def valid(self) -> bool:
        return self.hash_valid and self.signature_valid and self.chain_valid and self.sequence_valid


def verify_event(
    event: dict[str, Any],
    *,
    secret: str,
    expected_previous_hash: str | None,
    expected_next_sequence: int,
) -> IntegrityResult:
    calculated = compute_event_hash(event)
    return IntegrityResult(
        hash_valid=calculated == event["event_hash"],
        signature_valid=verify_signature(secret, event["event_hash"], event["signature"]),
        chain_valid=event.get("previous_hash") == expected_previous_hash,
        sequence_valid=int(event["sequence"]) == expected_next_sequence,
    )
