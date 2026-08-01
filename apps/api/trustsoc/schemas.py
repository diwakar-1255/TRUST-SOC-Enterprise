from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, EmailStr, Field

from trustsoc.models import SourceStatus, UserRole


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class RefreshRequest(BaseModel):
    refresh_token: str


class UserOut(ORMModel):
    id: UUID
    organization_id: UUID
    email: EmailStr
    role: UserRole
    active: bool


class AssetCreate(BaseModel):
    hostname: str = Field(min_length=1, max_length=255)
    asset_type: str = "endpoint"
    operating_system: str = "unknown"
    criticality: int = Field(default=3, ge=1, le=5)
    owner: str | None = None
    tags: dict[str, Any] = Field(default_factory=dict)


class AssetOut(AssetCreate, ORMModel):
    id: UUID
    organization_id: UUID
    active: bool
    created_at: datetime


class SourceCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    source_type: str = Field(min_length=1, max_length=100)
    asset_id: UUID | None = None
    expected_heartbeat_seconds: int = Field(default=60, ge=10, le=86400)
    expected_fields: list[str] = Field(default_factory=list)


class SourceCreated(BaseModel):
    id: UUID
    name: str
    source_type: str
    shared_secret: str
    message: str = "Store this secret securely; it is returned only once."


class SourceOut(ORMModel):
    id: UUID
    organization_id: UUID
    asset_id: UUID | None
    name: str
    source_type: str
    expected_heartbeat_seconds: int
    expected_fields: list[str]
    last_heartbeat_at: datetime | None
    status: SourceStatus
    trust_score: float
    active: bool


class TelemetryIn(BaseModel):
    source_id: UUID
    sequence: int = Field(ge=1)
    event_type: str = Field(min_length=1, max_length=120)
    observed_at: datetime
    body: dict[str, Any]
    previous_hash: str | None = None
    event_hash: str = Field(min_length=32, max_length=128)
    signature: str = Field(min_length=32, max_length=256)


class TelemetryAck(BaseModel):
    accepted: bool
    integrity_valid: bool
    chain_valid: bool
    fields_complete: bool
    trust_score: float
    reason: str | None = None


class RuleCreate(BaseModel):
    external_id: str
    name: str
    description: str = ""
    severity: Literal["low", "medium", "high", "critical"] = "medium"
    source_types: list[str] = Field(default_factory=list)
    required_fields: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    protected_asset_types: list[str] = Field(default_factory=list)
    enabled: bool = True


class RuleOut(RuleCreate, ORMModel):
    id: UUID
    organization_id: UUID
    created_at: datetime


class SimulationCreate(BaseModel):
    source_id: UUID
    simulation_type: Literal[
        "telemetry_gap",
        "event_drop",
        "event_duplicate",
        "event_delay",
        "schema_drift",
        "parser_field_loss",
    ]
    parameters: dict[str, Any] = Field(default_factory=dict)
    authorization_reference: str = Field(
        min_length=3, description="Change ticket, lab approval, or written authorization reference"
    )


class BlindnessFinding(BaseModel):
    source_id: UUID
    source_name: str
    source_status: str
    affected_rules: list[dict[str, Any]]
    affected_techniques: list[str]
    affected_assets: list[dict[str, Any]]
    coverage_loss_percent: float
    severity: str


class ReconstructionRequest(BaseModel):
    asset_id: UUID
    start: datetime
    end: datetime


class ReconstructedEvent(BaseModel):
    timestamp: datetime
    event_type: str
    classification: Literal["observed", "corroborated", "inferred", "reconstructed", "unverified"]
    confidence: float
    evidence_ids: list[UUID]
    summary: str


class SecurityAlertOut(ORMModel):
    id: UUID
    external_id: str
    integration: str
    event_timestamp: datetime
    agent_id: str | None
    agent_name: str | None
    agent_ip: str | None
    rule_id: str
    rule_level: int
    title: str
    description: str
    severity: str
    groups: list[str]
    mitre_techniques: list[str]
    mitre_tactics: list[str]
    status: str
    risk_score: int = 0
    alert_group_id: UUID | None = None
    incident_id: UUID | None = None
    acknowledged_at: datetime | None = None


class AlertGroupOut(ORMModel):
    id: UUID
    fingerprint: str
    integration: str
    window_start: datetime
    window_end: datetime
    first_seen: datetime
    last_seen: datetime
    occurrence_count: int
    agent_id: str | None
    agent_name: str | None
    agent_ip: str | None
    rule_id: str
    max_rule_level: int
    title: str
    severity: str
    risk_score: int
    groups: list[str]
    mitre_techniques: list[str]
    mitre_tactics: list[str]
    status: str
    assigned_to: UUID | None
    incident_id: UUID | None
    suppression_policy_id: UUID | None
    suppression_reason: str | None
    acknowledged_at: datetime | None
    created_at: datetime
    updated_at: datetime


class AlertGroupDetail(AlertGroupOut):
    raw_alerts: list[SecurityAlertOut] = []


class AlertGroupUpdate(BaseModel):
    status: Literal["new", "acknowledged", "investigating", "suppressed", "resolved"] | None = None
    assigned_to: UUID | None = None
    suppression_reason: str | None = Field(default=None, max_length=2000)


class IncidentCreateFromAlert(BaseModel):
    title: str | None = Field(default=None, max_length=500)
    description: str = Field(default="", max_length=5000)
    assigned_to: UUID | None = None


class IncidentUpdate(BaseModel):
    status: (
        Literal["open", "acknowledged", "investigating", "contained", "resolved", "closed"] | None
    ) = None
    severity: Literal["critical", "high", "medium", "low"] | None = None
    priority: Literal["P1", "P2", "P3", "P4"] | None = None
    assigned_to: UUID | None = None
    resolution_summary: str | None = Field(default=None, max_length=10000)


class SecurityIncidentOut(ORMModel):
    id: UUID
    case_number: str
    title: str
    description: str
    severity: str
    priority: str
    status: str
    risk_score: int
    source: str
    assigned_to: UUID | None
    created_by: UUID | None
    first_seen: datetime
    last_seen: datetime
    alert_group_count: int
    occurrence_count: int
    affected_assets: list[str]
    mitre_techniques: list[str]
    mitre_tactics: list[str]
    tags: dict[str, Any]
    sla_due_at: datetime | None
    acknowledged_at: datetime | None
    contained_at: datetime | None
    resolved_at: datetime | None
    resolution_summary: str | None
    created_at: datetime
    updated_at: datetime


class IncidentDetail(SecurityIncidentOut):
    alert_groups: list[AlertGroupOut] = []


class NoisePolicyCreate(BaseModel):
    name: str = Field(min_length=2, max_length=255)
    description: str = Field(default="", max_length=5000)
    enabled: bool = True
    action: Literal["suppress", "downgrade"] = "suppress"
    match_rule_ids: list[str] = []
    match_agent_pattern: str | None = Field(default=None, max_length=255)
    match_title_pattern: str | None = Field(default=None, max_length=500)
    match_severities: list[Literal["critical", "high", "medium", "low"]] = []
    match_groups: list[str] = []
    target_severity: Literal["critical", "high", "medium", "low"] | None = None
    reason: str = Field(default="", max_length=5000)
    expires_at: datetime | None = None


class NoisePolicyUpdate(BaseModel):
    enabled: bool | None = None
    action: Literal["suppress", "downgrade"] | None = None
    target_severity: Literal["critical", "high", "medium", "low"] | None = None
    reason: str | None = Field(default=None, max_length=5000)
    expires_at: datetime | None = None


class NoisePolicyOut(NoisePolicyCreate, ORMModel):
    id: UUID
    created_by: UUID | None
    created_at: datetime
    updated_at: datetime


class OperationsSummary(BaseModel):
    open_incidents: int = 0
    acknowledged_incidents: int = 0
    investigating_incidents: int = 0
    critical_incidents: int = 0
    grouped_alerts_24h: int = 0
    suppressed_alerts_24h: int = 0
    unacknowledged_groups: int = 0


class HoneypotEventOut(ORMModel):
    id: UUID
    external_event_id: str
    observed_at: datetime
    source_ip: str
    service: str
    event_type: str
    attack_type: str
    username: str | None
    path: str | None
    user_agent: str | None
    risk_score: int
    severity: str
    geo: dict[str, Any]


class HoneypotAttackerOut(ORMModel):
    id: UUID
    source_ip: str
    country: str | None
    city: str | None
    isp: str | None
    asn: str | None
    first_seen: datetime | None
    last_seen: datetime | None
    total_events: int
    risk_score: int
    severity: str


class HoneypotIntegrationStatusOut(BaseModel):
    enabled: bool
    status: str
    api_connected: bool = False
    grafana_url: str
    last_attempt_at: datetime | None = None
    last_success_at: datetime | None = None
    last_error: str | None = None
    synchronized_events: int = 0
    synchronized_alerts: int = 0
    synchronized_attackers: int = 0
    total_events: int = 0
    total_alerts: int = 0
    total_attackers: int = 0


class HoneypotSummaryOut(BaseModel):
    integration: HoneypotIntegrationStatusOut
    by_service: dict[str, int] = Field(default_factory=dict)
    alerts_by_severity: dict[str, int] = Field(default_factory=dict)
    recent_events: list[HoneypotEventOut] = Field(default_factory=list)
    top_attackers: list[HoneypotAttackerOut] = Field(default_factory=list)
    critical_alerts: list[SecurityAlertOut] = Field(default_factory=list)


class PortalAsset(BaseModel):
    id: UUID
    hostname: str
    asset_type: str
    operating_system: str
    ip_address: str | None = None
    criticality: int
    active: bool
    wazuh_agent_id: str | None = None
    wazuh_status: str | None = None
    telemetry_sources: int = 0
    source_health: str = "unknown"
    last_seen: datetime | None = None


class SeverityCounts(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0


class IntegrationStatusOut(BaseModel):
    enabled: bool
    status: str
    manager_connected: bool
    indexer_connected: bool
    last_attempt_at: datetime | None = None
    last_success_at: datetime | None = None
    last_error: str | None = None
    synchronized_agents: int = 0
    synchronized_alerts: int = 0


class PortalSummary(BaseModel):
    telemetry_trust_score: float
    protected_assets: int
    telemetry_sources: int
    critical_sources: int
    enabled_detections: int
    events_24h: int
    wazuh_agents_total: int
    wazuh_agents_active: int
    wazuh_agents_disconnected: int
    alerts_24h: int
    grouped_alerts_24h: int = 0
    suppressed_alerts_24h: int = 0
    open_incidents: int = 0
    severity: SeverityCounts
    mitre_techniques: list[dict[str, Any]]
    recent_alerts: list[SecurityAlertOut]
    integration: IntegrationStatusOut
