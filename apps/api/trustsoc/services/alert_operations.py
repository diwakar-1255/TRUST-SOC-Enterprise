from __future__ import annotations

import fnmatch
import hashlib
import math
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from trustsoc.config import get_settings
from trustsoc.models import AlertGroup, NoisePolicy, SecurityAlert, SecurityIncident

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def ensure_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def aggregation_window(timestamp: datetime, minutes: int) -> tuple[datetime, datetime]:
    timestamp = ensure_utc(timestamp)
    minute = timestamp.minute - (timestamp.minute % minutes)
    start = timestamp.replace(minute=minute, second=0, microsecond=0)
    return start, start + timedelta(minutes=minutes)


def alert_fingerprint(alert: SecurityAlert, window_start: datetime) -> str:
    subject = alert.agent_id or alert.agent_name or "manager"
    value = "|".join([alert.integration, subject, alert.rule_id, window_start.isoformat()])
    return hashlib.sha256(value.encode()).hexdigest()


def calculate_risk(
    severity: str,
    rule_level: int,
    occurrence_count: int,
    has_mitre: bool,
    asset_criticality: int = 3,
) -> int:
    base = {"low": 12, "medium": 38, "high": 68, "critical": 88}.get(severity, 20)
    score = base
    score += min(8, max(0, rule_level - 6))
    score += min(12, int(math.log2(max(1, occurrence_count)) * 3))
    score += 5 if has_mitre else 0
    score += max(0, min(5, asset_criticality) - 3) * 3
    return min(100, score)


def priority_for_severity(severity: str) -> str:
    return {"critical": "P1", "high": "P2", "medium": "P3", "low": "P4"}.get(severity, "P3")


def sla_due(severity: str, now: datetime | None = None) -> datetime:
    settings = get_settings()
    hours = {
        "critical": settings.incident_sla_critical_hours,
        "high": settings.incident_sla_high_hours,
        "medium": settings.incident_sla_medium_hours,
        "low": settings.incident_sla_low_hours,
    }.get(severity, settings.incident_sla_medium_hours)
    return (now or datetime.now(UTC)) + timedelta(hours=hours)


def case_number(now: datetime | None = None) -> str:
    value = now or datetime.now(UTC)
    return f"INC-{value:%Y%m%d}-{uuid.uuid4().hex[:8].upper()}"


def policy_matches(policy: NoisePolicy, alert: SecurityAlert) -> bool:
    now = datetime.now(UTC)
    if not policy.enabled or (policy.expires_at and ensure_utc(policy.expires_at) <= now):
        return False
    if policy.match_rule_ids and alert.rule_id not in policy.match_rule_ids:
        return False
    if policy.match_severities and alert.severity not in policy.match_severities:
        return False
    if policy.match_groups and not set(policy.match_groups).intersection(alert.groups or []):
        return False
    if policy.match_agent_pattern:
        if not fnmatch.fnmatchcase(
            (alert.agent_name or "").casefold(), policy.match_agent_pattern.casefold()
        ):
            return False
    if policy.match_title_pattern:
        if not fnmatch.fnmatchcase(
            (alert.title or "").casefold(), policy.match_title_pattern.casefold()
        ):
            return False
    return True


def apply_policy(alert: SecurityAlert, policies: list[NoisePolicy]) -> NoisePolicy | None:
    for policy in policies:
        if not policy_matches(policy, alert):
            continue
        alert.suppression_policy_id = policy.id
        if policy.action == "suppress":
            alert.status = "suppressed"
        elif policy.action == "downgrade" and policy.target_severity:
            alert.severity = policy.target_severity
        return policy
    return None


async def create_incident_for_group(
    db: AsyncSession,
    group: AlertGroup,
    *,
    created_by=None,
    title: str | None = None,
    description: str = "",
    assigned_to=None,
    source: str = "manual",
) -> SecurityIncident:
    if group.incident_id:
        existing = await db.get(SecurityIncident, group.incident_id)
        if existing:
            return existing

    incident = SecurityIncident(
        organization_id=group.organization_id,
        case_number=case_number(),
        title=title or f"{group.title} on {group.agent_name or 'Wazuh manager'}",
        description=description,
        severity=group.severity,
        priority=priority_for_severity(group.severity),
        status="open",
        risk_score=group.risk_score,
        source=source,
        assigned_to=assigned_to,
        created_by=created_by,
        first_seen=group.first_seen,
        last_seen=group.last_seen,
        alert_group_count=1,
        occurrence_count=group.occurrence_count,
        affected_assets=[group.agent_name] if group.agent_name else [],
        mitre_techniques=group.mitre_techniques or [],
        mitre_tactics=group.mitre_tactics or [],
        tags={"integration": group.integration, "rule_id": group.rule_id},
        sla_due_at=sla_due(group.severity),
    )
    db.add(incident)
    await db.flush()
    group.incident_id = incident.id
    group.status = "investigating"
    return incident


async def upsert_alert_group(
    db: AsyncSession,
    alert: SecurityAlert,
    policies: list[NoisePolicy],
    *,
    asset_criticality: int = 3,
) -> tuple[AlertGroup, bool, bool]:
    settings = get_settings()
    policy = apply_policy(alert, policies)
    window_start, window_end = aggregation_window(
        alert.event_timestamp, settings.alert_aggregation_window_minutes
    )
    fingerprint = alert_fingerprint(alert, window_start)
    group = await db.scalar(
        select(AlertGroup).where(
            AlertGroup.organization_id == alert.organization_id,
            AlertGroup.fingerprint == fingerprint,
        )
    )
    created = group is None
    if group is None:
        group = AlertGroup(
            organization_id=alert.organization_id,
            fingerprint=fingerprint,
            integration=alert.integration,
            window_start=window_start,
            window_end=window_end,
            first_seen=alert.event_timestamp,
            last_seen=alert.event_timestamp,
            occurrence_count=1,
            agent_id=alert.agent_id,
            agent_name=alert.agent_name,
            agent_ip=alert.agent_ip,
            rule_id=alert.rule_id,
            max_rule_level=alert.rule_level,
            title=alert.title,
            severity=alert.severity,
            risk_score=0,
            groups=alert.groups or [],
            mitre_techniques=alert.mitre_techniques or [],
            mitre_tactics=alert.mitre_tactics or [],
            status="suppressed" if alert.status == "suppressed" else "new",
            suppression_policy_id=policy.id if policy else None,
            suppression_reason=policy.reason if policy else None,
            sample_external_id=alert.external_id,
        )
        db.add(group)
        await db.flush()
    else:
        group.first_seen = min(ensure_utc(group.first_seen), ensure_utc(alert.event_timestamp))
        group.last_seen = max(ensure_utc(group.last_seen), ensure_utc(alert.event_timestamp))
        group.occurrence_count += 1
        group.max_rule_level = max(group.max_rule_level, alert.rule_level)
        if SEVERITY_ORDER.get(alert.severity, 0) > SEVERITY_ORDER.get(group.severity, 0):
            group.severity = alert.severity
        group.groups = sorted(set(group.groups or []).union(alert.groups or []))
        group.mitre_techniques = sorted(
            set(group.mitre_techniques or []).union(alert.mitre_techniques or [])
        )
        group.mitre_tactics = sorted(
            set(group.mitre_tactics or []).union(alert.mitre_tactics or [])
        )
        if policy and policy.action == "suppress":
            group.status = "suppressed"
            group.suppression_policy_id = policy.id
            group.suppression_reason = policy.reason

    group.risk_score = calculate_risk(
        group.severity,
        group.max_rule_level,
        group.occurrence_count,
        bool(group.mitre_techniques),
        asset_criticality,
    )
    alert.alert_group_id = group.id
    alert.risk_score = group.risk_score

    auto_incident = (
        settings.auto_incident_enabled
        and group.status != "suppressed"
        and not group.incident_id
        and (
            group.max_rule_level >= settings.auto_incident_min_rule_level
            or (
                group.occurrence_count >= settings.auto_incident_repetition_threshold
                and group.severity in {"medium", "high", "critical"}
            )
        )
    )
    incident_created = False
    if auto_incident:
        incident = await create_incident_for_group(
            db, group, source="automatic", description="Created by TRUST-SOC correlation policy."
        )
        alert.incident_id = incident.id
        incident_created = True
    elif group.incident_id:
        alert.incident_id = group.incident_id
        incident = await db.get(SecurityIncident, group.incident_id)
        if incident is not None:
            incident.last_seen = max(ensure_utc(incident.last_seen), ensure_utc(group.last_seen))
            incident.occurrence_count = group.occurrence_count
            incident.risk_score = max(incident.risk_score, group.risk_score)
            if SEVERITY_ORDER.get(group.severity, 0) > SEVERITY_ORDER.get(incident.severity, 0):
                incident.severity = group.severity
                incident.priority = priority_for_severity(group.severity)
                incident.sla_due_at = min(
                    ensure_utc(incident.sla_due_at)
                    if incident.sla_due_at
                    else sla_due(group.severity),
                    sla_due(group.severity),
                )
            incident.mitre_techniques = sorted(
                set(incident.mitre_techniques or []).union(group.mitre_techniques or [])
            )
            incident.mitre_tactics = sorted(
                set(incident.mitre_tactics or []).union(group.mitre_tactics or [])
            )
    return group, created, incident_created


async def rebuild_alert_groups(db: AsyncSession, organization_id=None) -> dict[str, Any]:
    statement = select(SecurityAlert).where(SecurityAlert.alert_group_id.is_(None))
    if organization_id is not None:
        statement = statement.where(SecurityAlert.organization_id == organization_id)
    alerts = list(await db.scalars(statement.order_by(SecurityAlert.event_timestamp)))
    if not alerts:
        return {"alerts_processed": 0, "groups_created": 0, "incidents_created": 0}

    organizations = sorted({alert.organization_id for alert in alerts}, key=str)
    policy_map: dict[Any, list[NoisePolicy]] = {}
    for org_id in organizations:
        policy_map[org_id] = list(
            await db.scalars(
                select(NoisePolicy).where(
                    NoisePolicy.organization_id == org_id,
                    NoisePolicy.enabled.is_(True),
                )
            )
        )

    groups_created = 0
    before_incidents = set(await db.scalars(select(SecurityIncident.id)))
    for alert in alerts:
        _, created, _ = await upsert_alert_group(db, alert, policy_map[alert.organization_id])
        groups_created += int(created)
    await db.commit()
    after_incidents = set(await db.scalars(select(SecurityIncident.id)))
    return {
        "alerts_processed": len(alerts),
        "groups_created": groups_created,
        "incidents_created": len(after_incidents - before_incidents),
    }
