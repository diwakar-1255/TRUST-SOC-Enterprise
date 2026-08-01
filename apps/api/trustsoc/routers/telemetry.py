from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from trustsoc.database import get_db
from trustsoc.metrics import SOURCE_TRUST_SCORE, TELEMETRY_EVENTS, TELEMETRY_LATENCY
from trustsoc.models import SourceStatus, TelemetryEvent, TelemetrySource
from trustsoc.schemas import TelemetryAck, TelemetryIn
from trustsoc.security import decrypt_secret
from trustsoc.services.integrity import verify_event
from trustsoc.services.trust_score import TrustInputs, calculate_trust_score, score_status

router = APIRouter(prefix="/telemetry", tags=["telemetry ingestion"])


@router.post("/ingest", response_model=TelemetryAck)
async def ingest(payload: TelemetryIn, db: AsyncSession = Depends(get_db)) -> TelemetryAck:
    source = await db.scalar(
        select(TelemetrySource)
        .where(TelemetrySource.id == payload.source_id, TelemetrySource.active.is_(True))
        .with_for_update()
    )
    if source is None:
        raise HTTPException(404, "Unknown or inactive source")

    event_dict = payload.model_dump()
    result = verify_event(
        event_dict,
        secret=decrypt_secret(source.encrypted_shared_secret),
        expected_previous_hash=source.last_event_hash,
        expected_next_sequence=source.last_sequence + 1,
    )
    missing_fields = sorted(set(source.expected_fields) - set(payload.body.keys()))
    fields_complete = not missing_fields
    now = datetime.now(UTC)
    latency_ms = max(0, int((now - payload.observed_at).total_seconds() * 1000))
    latency_ratio = max(0.0, 1.0 - min(latency_ms / 300000, 1.0))
    score = calculate_trust_score(
        TrustInputs(
            heartbeat_ratio=1.0,
            integrity_ratio=1.0 if result.hash_valid and result.signature_valid else 0.0,
            chain_ratio=1.0 if result.chain_valid and result.sequence_valid else 0.0,
            completeness_ratio=1.0 if fields_complete else 0.0,
            latency_ratio=latency_ratio,
        )
    )

    if not result.valid:
        source.trust_score = score
        source.status = SourceStatus.critical
        await db.commit()
        TELEMETRY_EVENTS.labels(payload.event_type, "integrity_failure").inc()
        SOURCE_TRUST_SCORE.labels(str(source.id), source.source_type).set(score)
        return TelemetryAck(
            accepted=False,
            integrity_valid=result.hash_valid and result.signature_valid,
            chain_valid=result.chain_valid and result.sequence_valid,
            fields_complete=fields_complete,
            trust_score=score,
            reason=f"Event quarantined: missing_fields={missing_fields}; integrity={result}",
        )

    event = TelemetryEvent(
        organization_id=source.organization_id,
        source_id=source.id,
        sequence=payload.sequence,
        event_type=payload.event_type,
        observed_at=payload.observed_at,
        body=payload.body,
        previous_hash=payload.previous_hash,
        event_hash=payload.event_hash,
        signature=payload.signature,
        integrity_valid=result.hash_valid and result.signature_valid,
        chain_valid=result.chain_valid and result.sequence_valid,
        fields_complete=fields_complete,
        latency_ms=latency_ms,
        classification="observed",
    )
    db.add(event)
    source.last_heartbeat_at = (
        now if payload.event_type in {"heartbeat", "canary"} else source.last_heartbeat_at
    )
    source.trust_score = score
    source.status = SourceStatus(score_status(score))
    source.last_sequence = payload.sequence
    source.last_event_hash = payload.event_hash
    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        TELEMETRY_EVENTS.labels(payload.event_type, "duplicate").inc()
        raise HTTPException(409, "Duplicate sequence or replay detected") from None

    TELEMETRY_EVENTS.labels(payload.event_type, "accepted").inc()
    TELEMETRY_LATENCY.observe(latency_ms / 1000)
    SOURCE_TRUST_SCORE.labels(str(source.id), source.source_type).set(score)
    return TelemetryAck(
        accepted=True,
        integrity_valid=result.hash_valid and result.signature_valid,
        chain_valid=result.chain_valid and result.sequence_valid,
        fields_complete=fields_complete,
        trust_score=score,
        reason=None
        if result.valid and fields_complete
        else f"missing_fields={missing_fields}; integrity={result}",
    )
