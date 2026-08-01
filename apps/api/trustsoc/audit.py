from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from trustsoc.models import AuditEvent


async def write_audit(
    db: AsyncSession,
    *,
    action: str,
    resource_type: str,
    organization_id: UUID | None,
    actor_id: UUID | None = None,
    resource_id: str | None = None,
    outcome: str = "success",
    request_id: str | None = None,
    source_ip: str | None = None,
    details: dict | None = None,
) -> None:
    db.add(
        AuditEvent(
            action=action,
            resource_type=resource_type,
            organization_id=organization_id,
            actor_id=actor_id,
            resource_id=resource_id,
            outcome=outcome,
            request_id=request_id,
            source_ip=source_ip,
            details=details or {},
        )
    )
