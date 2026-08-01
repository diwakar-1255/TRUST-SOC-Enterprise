from datetime import UTC, datetime
from uuid import UUID

from celery import Celery
from sqlalchemy import select

from trustsoc.config import get_settings
from trustsoc.database import SessionLocal
from trustsoc.metrics import SIMULATION_RUNS
from trustsoc.models import SimulationRun

settings = get_settings()
celery_app = Celery("trustsoc", broker=settings.redis_url, backend=settings.redis_url)
celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
)
celery_app.conf.beat_schedule = {
    "evaluate-heartbeats-every-minute": {
        "task": "trustsoc.worker.evaluate_heartbeats",
        "schedule": 60.0,
    }
}


@celery_app.task(name="trustsoc.worker.execute_simulation")
def execute_simulation(run_id: str) -> None:
    import asyncio

    asyncio.run(_execute_simulation(UUID(run_id)))


async def _execute_simulation(run_id: UUID) -> None:
    async with SessionLocal() as db:
        run = await db.scalar(
            select(SimulationRun).where(SimulationRun.id == run_id).with_for_update()
        )
        if run is None:
            return
        run.status = "running"
        run.started_at = datetime.now(UTC)
        await db.commit()
        # Safe by design: this creates a test specification and expected validation checks.
        run.status = "completed"
        run.completed_at = datetime.now(UTC)
        run.result = {
            "synthetic": True,
            "simulation_type": run.simulation_type,
            "expected_checks": [
                "heartbeat_gap",
                "integrity_change",
                "blindness_recalculation",
                "recovery_validation",
            ],
            "message": "Simulation plan completed without executing destructive host actions.",
        }
        await db.commit()
        SIMULATION_RUNS.labels(run.simulation_type, run.status).inc()


@celery_app.task(name="trustsoc.worker.evaluate_heartbeats")
def evaluate_heartbeats() -> None:
    import asyncio

    asyncio.run(_evaluate_heartbeats())


async def _evaluate_heartbeats() -> None:
    from trustsoc.models import SourceStatus, TelemetrySource

    async with SessionLocal() as db:
        sources = list(
            await db.scalars(select(TelemetrySource).where(TelemetrySource.active.is_(True)))
        )
        now = datetime.now(UTC)
        for source in sources:
            if source.last_heartbeat_at is None:
                source.status = SourceStatus.unknown
                source.trust_score = min(source.trust_score, 20)
                continue
            age = (now - source.last_heartbeat_at).total_seconds()
            if age > source.expected_heartbeat_seconds * 3:
                source.status = SourceStatus.critical
                source.trust_score = min(source.trust_score, 40)
            elif age > source.expected_heartbeat_seconds * 1.5:
                source.status = SourceStatus.degraded
                source.trust_score = min(source.trust_score, 75)
        await db.commit()
