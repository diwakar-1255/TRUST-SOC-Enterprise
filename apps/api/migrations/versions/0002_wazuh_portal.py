"""Add Wazuh synchronization and customer portal models."""

from alembic import op

from trustsoc.models import IntegrationState, SecurityAlert

revision = "0002_wazuh_portal"
down_revision = "0001_initial"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    SecurityAlert.__table__.create(bind=bind, checkfirst=True)
    IntegrationState.__table__.create(bind=bind, checkfirst=True)


def downgrade() -> None:
    bind = op.get_bind()
    IntegrationState.__table__.drop(bind=bind, checkfirst=True)
    SecurityAlert.__table__.drop(bind=bind, checkfirst=True)
