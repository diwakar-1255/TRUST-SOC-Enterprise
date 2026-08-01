from trustsoc.services.trust_score import TrustInputs, calculate_trust_score, score_status


def test_perfect_score():
    assert calculate_trust_score(TrustInputs(1, 1, 1, 1, 1)) == 100
    assert score_status(100) == "healthy"


def test_integrity_failure_is_severe():
    score = calculate_trust_score(TrustInputs(1, 0, 0, 1, 1))
    assert score == 50
    assert score_status(score) == "critical"
