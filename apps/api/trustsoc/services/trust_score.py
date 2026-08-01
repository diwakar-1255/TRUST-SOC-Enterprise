from dataclasses import dataclass


@dataclass(frozen=True)
class TrustInputs:
    heartbeat_ratio: float
    integrity_ratio: float
    chain_ratio: float
    completeness_ratio: float
    latency_ratio: float


def clamp(value: float) -> float:
    return max(0.0, min(1.0, value))


def calculate_trust_score(inputs: TrustInputs) -> float:
    """Weighted score where integrity and continuity dominate availability."""
    weighted = (
        clamp(inputs.heartbeat_ratio) * 0.20
        + clamp(inputs.integrity_ratio) * 0.25
        + clamp(inputs.chain_ratio) * 0.25
        + clamp(inputs.completeness_ratio) * 0.20
        + clamp(inputs.latency_ratio) * 0.10
    )
    return round(weighted * 100, 2)


def score_status(score: float) -> str:
    if score >= 90:
        return "healthy"
    if score >= 70:
        return "degraded"
    return "critical"
