"""alert correlation, noise policies, and incidents

Revision ID: 0003_incident_noise
Revises: 0002_wazuh_portal
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0003_incident_noise"
down_revision: str | None = "0002_wazuh_portal"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "noise_policies",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("description", sa.Text(), nullable=False, server_default=""),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("action", sa.String(30), nullable=False, server_default="suppress"),
        sa.Column("match_rule_ids", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("match_agent_pattern", sa.String(255)),
        sa.Column("match_title_pattern", sa.String(500)),
        sa.Column("match_severities", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("match_groups", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("target_severity", sa.String(30)),
        sa.Column("reason", sa.Text(), nullable=False, server_default=""),
        sa.Column("expires_at", sa.DateTime(timezone=True)),
        sa.Column("created_by", postgresql.UUID(as_uuid=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"], ondelete="SET NULL"),
        sa.UniqueConstraint("organization_id", "name", name="uq_noise_policy_org_name"),
    )
    op.create_index("ix_noise_policy_org_enabled", "noise_policies", ["organization_id", "enabled"])

    op.create_table(
        "security_incidents",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("case_number", sa.String(64), nullable=False),
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("description", sa.Text(), nullable=False, server_default=""),
        sa.Column("severity", sa.String(30), nullable=False),
        sa.Column("priority", sa.String(10), nullable=False, server_default="P3"),
        sa.Column("status", sa.String(30), nullable=False, server_default="open"),
        sa.Column("risk_score", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("source", sa.String(50), nullable=False, server_default="manual"),
        sa.Column("assigned_to", postgresql.UUID(as_uuid=True)),
        sa.Column("created_by", postgresql.UUID(as_uuid=True)),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("alert_group_count", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("occurrence_count", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("affected_assets", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("mitre_techniques", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("mitre_tactics", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("tags", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("sla_due_at", sa.DateTime(timezone=True)),
        sa.Column("acknowledged_at", sa.DateTime(timezone=True)),
        sa.Column("contained_at", sa.DateTime(timezone=True)),
        sa.Column("resolved_at", sa.DateTime(timezone=True)),
        sa.Column("resolution_summary", sa.Text()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["assigned_to"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"], ondelete="SET NULL"),
        sa.UniqueConstraint("organization_id", "case_number", name="uq_incident_org_case"),
    )
    op.create_index("ix_incident_org_status", "security_incidents", ["organization_id", "status"])
    op.create_index(
        "ix_incident_org_severity", "security_incidents", ["organization_id", "severity"]
    )
    op.create_index(
        "ix_incident_org_updated", "security_incidents", ["organization_id", "updated_at"]
    )

    op.create_table(
        "alert_groups",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("fingerprint", sa.String(128), nullable=False),
        sa.Column("integration", sa.String(50), nullable=False, server_default="wazuh"),
        sa.Column("window_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("window_end", sa.DateTime(timezone=True), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("occurrence_count", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("agent_id", sa.String(100)),
        sa.Column("agent_name", sa.String(255)),
        sa.Column("agent_ip", sa.String(100)),
        sa.Column("rule_id", sa.String(100), nullable=False),
        sa.Column("max_rule_level", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("severity", sa.String(30), nullable=False),
        sa.Column("risk_score", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("groups", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("mitre_techniques", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("mitre_tactics", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("status", sa.String(30), nullable=False, server_default="new"),
        sa.Column("assigned_to", postgresql.UUID(as_uuid=True)),
        sa.Column("incident_id", postgresql.UUID(as_uuid=True)),
        sa.Column("suppression_policy_id", postgresql.UUID(as_uuid=True)),
        sa.Column("sample_external_id", sa.String(512)),
        sa.Column("suppression_reason", sa.Text()),
        sa.Column("acknowledged_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["assigned_to"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["incident_id"], ["security_incidents.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(
            ["suppression_policy_id"], ["noise_policies.id"], ondelete="SET NULL"
        ),
        sa.UniqueConstraint(
            "organization_id", "fingerprint", name="uq_alert_group_org_fingerprint"
        ),
    )
    op.create_index(
        "ix_alert_group_org_last_seen", "alert_groups", ["organization_id", "last_seen"]
    )
    op.create_index("ix_alert_group_org_status", "alert_groups", ["organization_id", "status"])
    op.create_index("ix_alert_group_org_severity", "alert_groups", ["organization_id", "severity"])

    op.add_column(
        "security_alerts", sa.Column("risk_score", sa.Integer(), nullable=False, server_default="0")
    )
    op.add_column("security_alerts", sa.Column("alert_group_id", postgresql.UUID(as_uuid=True)))
    op.add_column("security_alerts", sa.Column("incident_id", postgresql.UUID(as_uuid=True)))
    op.add_column(
        "security_alerts", sa.Column("suppression_policy_id", postgresql.UUID(as_uuid=True))
    )
    op.add_column("security_alerts", sa.Column("assigned_to", postgresql.UUID(as_uuid=True)))
    op.add_column("security_alerts", sa.Column("acknowledged_at", sa.DateTime(timezone=True)))
    op.create_foreign_key(
        "fk_alert_group",
        "security_alerts",
        "alert_groups",
        ["alert_group_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_foreign_key(
        "fk_alert_incident",
        "security_alerts",
        "security_incidents",
        ["incident_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_foreign_key(
        "fk_alert_noise_policy",
        "security_alerts",
        "noise_policies",
        ["suppression_policy_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_foreign_key(
        "fk_alert_assignee",
        "security_alerts",
        "users",
        ["assigned_to"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_index("ix_security_alerts_risk_score", "security_alerts", ["risk_score"])
    op.create_index("ix_security_alerts_alert_group_id", "security_alerts", ["alert_group_id"])
    op.create_index("ix_security_alerts_incident_id", "security_alerts", ["incident_id"])
    op.create_index(
        "ix_security_alerts_suppression_policy_id", "security_alerts", ["suppression_policy_id"]
    )
    op.create_index("ix_security_alerts_assigned_to", "security_alerts", ["assigned_to"])


def downgrade() -> None:
    op.drop_index("ix_security_alerts_assigned_to", table_name="security_alerts")
    op.drop_index("ix_security_alerts_suppression_policy_id", table_name="security_alerts")
    op.drop_index("ix_security_alerts_incident_id", table_name="security_alerts")
    op.drop_index("ix_security_alerts_alert_group_id", table_name="security_alerts")
    op.drop_index("ix_security_alerts_risk_score", table_name="security_alerts")
    op.drop_constraint("fk_alert_assignee", "security_alerts", type_="foreignkey")
    op.drop_constraint("fk_alert_noise_policy", "security_alerts", type_="foreignkey")
    op.drop_constraint("fk_alert_incident", "security_alerts", type_="foreignkey")
    op.drop_constraint("fk_alert_group", "security_alerts", type_="foreignkey")
    for column in [
        "acknowledged_at",
        "assigned_to",
        "suppression_policy_id",
        "incident_id",
        "alert_group_id",
        "risk_score",
    ]:
        op.drop_column("security_alerts", column)
    op.drop_table("alert_groups")
    op.drop_table("security_incidents")
    op.drop_table("noise_policies")
