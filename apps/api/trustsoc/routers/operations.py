from datetime import UTC, datetime, timedelta
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from trustsoc.audit import write_audit
from trustsoc.database import get_db
from trustsoc.dependencies import current_user, require_roles
from trustsoc.models import (
    AlertGroup,
    NoisePolicy,
    SecurityAlert,
    SecurityIncident,
    User,
    UserRole,
)
from trustsoc.schemas import (
    AlertGroupDetail,
    AlertGroupOut,
    AlertGroupUpdate,
    IncidentCreateFromAlert,
    IncidentDetail,
    IncidentUpdate,
    NoisePolicyCreate,
    NoisePolicyOut,
    NoisePolicyUpdate,
    OperationsSummary,
    SecurityIncidentOut,
)
from trustsoc.services.alert_operations import (
    calculate_risk,
    create_incident_for_group,
    policy_matches,
)

router = APIRouter(prefix="/operations", tags=["security operations"])
WRITE_ROLES = (
    UserRole.tenant_admin,
    UserRole.soc_manager,
    UserRole.soc_analyst,
    UserRole.incident_responder,
)


async def _group(db: AsyncSession, organization_id, group_id: UUID) -> AlertGroup:
    group = await db.scalar(
        select(AlertGroup).where(
            AlertGroup.id == group_id,
            AlertGroup.organization_id == organization_id,
        )
    )
    if group is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Alert group not found")
    return group


async def _incident(db: AsyncSession, organization_id, incident_id: UUID) -> SecurityIncident:
    incident = await db.scalar(
        select(SecurityIncident).where(
            SecurityIncident.id == incident_id,
            SecurityIncident.organization_id == organization_id,
        )
    )
    if incident is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Incident not found")
    return incident


@router.get("/summary", response_model=OperationsSummary)
async def operations_summary(
    user: User = Depends(current_user), db: AsyncSession = Depends(get_db)
):
    org = user.organization_id
    since = datetime.now(UTC) - timedelta(hours=24)

    async def count_incidents(*statuses: str, severity: str | None = None) -> int:
        statement = (
            select(func.count())
            .select_from(SecurityIncident)
            .where(SecurityIncident.organization_id == org)
        )
        if statuses:
            statement = statement.where(SecurityIncident.status.in_(statuses))
        if severity:
            statement = statement.where(SecurityIncident.severity == severity)
        return int(await db.scalar(statement) or 0)

    grouped = int(
        await db.scalar(
            select(func.count())
            .select_from(AlertGroup)
            .where(
                AlertGroup.organization_id == org,
                AlertGroup.last_seen >= since,
            )
        )
        or 0
    )
    suppressed = int(
        await db.scalar(
            select(func.count())
            .select_from(AlertGroup)
            .where(
                AlertGroup.organization_id == org,
                AlertGroup.last_seen >= since,
                AlertGroup.status == "suppressed",
            )
        )
        or 0
    )
    unacknowledged = int(
        await db.scalar(
            select(func.count())
            .select_from(AlertGroup)
            .where(
                AlertGroup.organization_id == org,
                AlertGroup.status == "new",
            )
        )
        or 0
    )
    return OperationsSummary(
        open_incidents=await count_incidents("open", "acknowledged", "investigating", "contained"),
        acknowledged_incidents=await count_incidents("acknowledged"),
        investigating_incidents=await count_incidents("investigating"),
        critical_incidents=await count_incidents(
            "open", "acknowledged", "investigating", "contained", severity="critical"
        ),
        grouped_alerts_24h=grouped,
        suppressed_alerts_24h=suppressed,
        unacknowledged_groups=unacknowledged,
    )


@router.get("/alert-groups", response_model=list[AlertGroupOut])
async def list_alert_groups(
    severity: str | None = Query(default=None),
    status_filter: str | None = Query(default=None, alias="status"),
    agent_name: str | None = Query(default=None),
    search: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_db),
):
    statement = select(AlertGroup).where(AlertGroup.organization_id == user.organization_id)
    if severity:
        statement = statement.where(AlertGroup.severity == severity.lower())
    if status_filter:
        statement = statement.where(AlertGroup.status == status_filter.lower())
    if agent_name:
        statement = statement.where(AlertGroup.agent_name.ilike(f"%{agent_name}%"))
    if search:
        value = f"%{search}%"
        statement = statement.where(
            or_(
                AlertGroup.title.ilike(value),
                AlertGroup.rule_id.ilike(value),
                AlertGroup.agent_name.ilike(value),
            )
        )
    groups = await db.scalars(
        statement.order_by(AlertGroup.last_seen.desc()).offset(offset).limit(limit)
    )
    return list(groups)


@router.get("/alert-groups/{group_id}", response_model=AlertGroupDetail)
async def alert_group_detail(
    group_id: UUID,
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_db),
):
    group = await _group(db, user.organization_id, group_id)
    alerts = list(
        await db.scalars(
            select(SecurityAlert)
            .where(
                SecurityAlert.organization_id == user.organization_id,
                SecurityAlert.alert_group_id == group.id,
            )
            .order_by(SecurityAlert.event_timestamp.desc())
            .limit(200)
        )
    )
    return AlertGroupDetail.model_validate(group, from_attributes=True).model_copy(
        update={"raw_alerts": alerts}
    )


@router.patch("/alert-groups/{group_id}", response_model=AlertGroupOut)
async def update_alert_group(
    group_id: UUID,
    payload: AlertGroupUpdate,
    user: User = Depends(require_roles(*WRITE_ROLES)),
    db: AsyncSession = Depends(get_db),
):
    group = await _group(db, user.organization_id, group_id)
    if payload.status == "suppressed" and group.incident_id:
        raise HTTPException(409, "Resolve or close the linked incident before suppression")
    changes = payload.model_dump(exclude_unset=True)
    for key, value in changes.items():
        setattr(group, key, value)
    if payload.status == "acknowledged" and group.acknowledged_at is None:
        group.acknowledged_at = datetime.now(UTC)
    if payload.status:
        alert_values = {"status": payload.status}
        if payload.status == "acknowledged":
            alert_values["acknowledged_at"] = group.acknowledged_at
        await db.execute(
            SecurityAlert.__table__.update()
            .where(SecurityAlert.alert_group_id == group.id)
            .values(**alert_values)
        )
    await write_audit(
        db,
        action="alert_group.update",
        resource_type="alert_group",
        resource_id=str(group.id),
        organization_id=user.organization_id,
        actor_id=user.id,
        details=changes,
    )
    await db.commit()
    await db.refresh(group)
    return group


@router.post("/alert-groups/{group_id}/incident", response_model=SecurityIncidentOut)
async def create_incident(
    group_id: UUID,
    payload: IncidentCreateFromAlert,
    user: User = Depends(require_roles(*WRITE_ROLES)),
    db: AsyncSession = Depends(get_db),
):
    group = await _group(db, user.organization_id, group_id)
    incident = await create_incident_for_group(
        db,
        group,
        created_by=user.id,
        title=payload.title,
        description=payload.description,
        assigned_to=payload.assigned_to,
        source="manual",
    )
    await db.execute(
        SecurityAlert.__table__.update()
        .where(SecurityAlert.alert_group_id == group.id)
        .values(incident_id=incident.id)
    )
    await write_audit(
        db,
        action="incident.create_from_alert_group",
        resource_type="incident",
        resource_id=str(incident.id),
        organization_id=user.organization_id,
        actor_id=user.id,
        details={"alert_group_id": str(group.id), "case_number": incident.case_number},
    )
    await db.commit()
    await db.refresh(incident)
    return incident


@router.get("/incidents", response_model=list[SecurityIncidentOut])
async def list_incidents(
    status_filter: str | None = Query(default=None, alias="status"),
    severity: str | None = Query(default=None),
    search: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_db),
):
    statement = select(SecurityIncident).where(
        SecurityIncident.organization_id == user.organization_id
    )
    if status_filter:
        statement = statement.where(SecurityIncident.status == status_filter)
    if severity:
        statement = statement.where(SecurityIncident.severity == severity)
    if search:
        value = f"%{search}%"
        statement = statement.where(
            or_(
                SecurityIncident.case_number.ilike(value),
                SecurityIncident.title.ilike(value),
            )
        )
    rows = await db.scalars(statement.order_by(SecurityIncident.updated_at.desc()).limit(limit))
    return list(rows)


@router.get("/incidents/{incident_id}", response_model=IncidentDetail)
async def incident_detail(
    incident_id: UUID,
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_db),
):
    incident = await _incident(db, user.organization_id, incident_id)
    groups = list(
        await db.scalars(
            select(AlertGroup)
            .where(
                AlertGroup.organization_id == user.organization_id,
                AlertGroup.incident_id == incident.id,
            )
            .order_by(AlertGroup.last_seen.desc())
        )
    )
    return IncidentDetail.model_validate(incident, from_attributes=True).model_copy(
        update={"alert_groups": groups}
    )


@router.patch("/incidents/{incident_id}", response_model=SecurityIncidentOut)
async def update_incident(
    incident_id: UUID,
    payload: IncidentUpdate,
    user: User = Depends(require_roles(*WRITE_ROLES)),
    db: AsyncSession = Depends(get_db),
):
    incident = await _incident(db, user.organization_id, incident_id)
    changes = payload.model_dump(exclude_unset=True)
    now = datetime.now(UTC)
    for key, value in changes.items():
        setattr(incident, key, value)
    if payload.status == "acknowledged" and incident.acknowledged_at is None:
        incident.acknowledged_at = now
    elif payload.status == "contained" and incident.contained_at is None:
        incident.contained_at = now
    elif payload.status in {"resolved", "closed"} and incident.resolved_at is None:
        incident.resolved_at = now

    if payload.status:
        group_status = {
            "open": "new",
            "acknowledged": "acknowledged",
            "investigating": "investigating",
            "contained": "resolved",
            "resolved": "resolved",
            "closed": "resolved",
        }[payload.status]
        await db.execute(
            AlertGroup.__table__.update()
            .where(AlertGroup.incident_id == incident.id)
            .values(status=group_status)
        )
        await db.execute(
            SecurityAlert.__table__.update()
            .where(SecurityAlert.incident_id == incident.id)
            .values(status=group_status)
        )
    await write_audit(
        db,
        action="incident.update",
        resource_type="incident",
        resource_id=str(incident.id),
        organization_id=user.organization_id,
        actor_id=user.id,
        details=changes,
    )
    await db.commit()
    await db.refresh(incident)
    return incident


@router.get("/noise-policies", response_model=list[NoisePolicyOut])
async def list_noise_policies(
    user: User = Depends(current_user), db: AsyncSession = Depends(get_db)
):
    policies = await db.scalars(
        select(NoisePolicy)
        .where(NoisePolicy.organization_id == user.organization_id)
        .order_by(NoisePolicy.created_at.desc())
    )
    return list(policies)


@router.post("/noise-policies", response_model=NoisePolicyOut, status_code=201)
async def create_noise_policy(
    payload: NoisePolicyCreate,
    user: User = Depends(require_roles(*WRITE_ROLES)),
    db: AsyncSession = Depends(get_db),
):
    if payload.action == "downgrade" and not payload.target_severity:
        raise HTTPException(422, "target_severity is required for downgrade policies")
    if not any(
        [
            payload.match_rule_ids,
            payload.match_agent_pattern,
            payload.match_title_pattern,
            payload.match_severities,
            payload.match_groups,
        ]
    ):
        raise HTTPException(
            422, "At least one rule, endpoint, title, severity, or group matcher is required"
        )
    duplicate = await db.scalar(
        select(NoisePolicy.id).where(
            NoisePolicy.organization_id == user.organization_id,
            NoisePolicy.name == payload.name,
        )
    )
    if duplicate:
        raise HTTPException(409, "A noise policy with this name already exists")
    policy = NoisePolicy(
        organization_id=user.organization_id,
        created_by=user.id,
        **payload.model_dump(),
    )
    db.add(policy)
    await db.flush()

    matched_groups = 0
    groups = list(
        await db.scalars(
            select(AlertGroup).where(AlertGroup.organization_id == user.organization_id)
        )
    )
    for group in groups:
        if not policy_matches(policy, group):
            continue
        matched_groups += 1
        group.suppression_policy_id = policy.id
        if policy.action == "suppress":
            group.status = "suppressed"
            group.suppression_reason = policy.reason
            await db.execute(
                SecurityAlert.__table__.update()
                .where(SecurityAlert.alert_group_id == group.id)
                .values(status="suppressed", suppression_policy_id=policy.id)
            )
        elif policy.action == "downgrade" and policy.target_severity:
            group.severity = policy.target_severity
            group.risk_score = calculate_risk(
                group.severity,
                group.max_rule_level,
                group.occurrence_count,
                bool(group.mitre_techniques),
            )
            await db.execute(
                SecurityAlert.__table__.update()
                .where(SecurityAlert.alert_group_id == group.id)
                .values(
                    severity=policy.target_severity,
                    risk_score=group.risk_score,
                    suppression_policy_id=policy.id,
                )
            )

    await write_audit(
        db,
        action="noise_policy.create",
        resource_type="noise_policy",
        resource_id=str(policy.id),
        organization_id=user.organization_id,
        actor_id=user.id,
        details={
            "name": policy.name,
            "action": policy.action,
            "matched_existing_groups": matched_groups,
        },
    )
    await db.commit()
    await db.refresh(policy)
    return policy


@router.patch("/noise-policies/{policy_id}", response_model=NoisePolicyOut)
async def update_noise_policy(
    policy_id: UUID,
    payload: NoisePolicyUpdate,
    user: User = Depends(require_roles(*WRITE_ROLES)),
    db: AsyncSession = Depends(get_db),
):
    policy = await db.scalar(
        select(NoisePolicy).where(
            NoisePolicy.id == policy_id,
            NoisePolicy.organization_id == user.organization_id,
        )
    )
    if policy is None:
        raise HTTPException(404, "Noise policy not found")
    changes = payload.model_dump(exclude_unset=True)
    for key, value in changes.items():
        setattr(policy, key, value)
    await write_audit(
        db,
        action="noise_policy.update",
        resource_type="noise_policy",
        resource_id=str(policy.id),
        organization_id=user.organization_id,
        actor_id=user.id,
        details=changes,
    )
    await db.commit()
    await db.refresh(policy)
    return policy


@router.delete("/noise-policies/{policy_id}", status_code=204)
async def delete_noise_policy(
    policy_id: UUID,
    user: User = Depends(require_roles(*WRITE_ROLES)),
    db: AsyncSession = Depends(get_db),
):
    policy = await db.scalar(
        select(NoisePolicy).where(
            NoisePolicy.id == policy_id,
            NoisePolicy.organization_id == user.organization_id,
        )
    )
    if policy is None:
        raise HTTPException(404, "Noise policy not found")
    await write_audit(
        db,
        action="noise_policy.delete",
        resource_type="noise_policy",
        resource_id=str(policy.id),
        organization_id=user.organization_id,
        actor_id=user.id,
        details={"name": policy.name},
    )
    await db.delete(policy)
    await db.commit()
