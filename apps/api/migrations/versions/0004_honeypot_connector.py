"""Add deployed honeypot SOC connector models after incident workflow.

Revision ID: 0004_honeypot_connector
Revises: 0003_incident_noise
"""

from alembic import op

from trustsoc.models import HoneypotAttacker, HoneypotEvent

revision = "0004_honeypot_connector"
down_revision = "0003_incident_noise"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    HoneypotEvent.__table__.create(bind=bind, checkfirst=True)
    HoneypotAttacker.__table__.create(bind=bind, checkfirst=True)


def downgrade() -> None:
    bind = op.get_bind()
    HoneypotAttacker.__table__.drop(bind=bind, checkfirst=True)
    HoneypotEvent.__table__.drop(bind=bind, checkfirst=True)
