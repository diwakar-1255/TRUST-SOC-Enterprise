"""Initial TRUST-SOC schema."""

from alembic import op

from trustsoc import models  # noqa: F401
from trustsoc.database import Base

revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None

_PHASE_TWO_TABLES = {"security_alerts", "integration_states"}


def upgrade() -> None:
    bind = op.get_bind()
    for table in Base.metadata.sorted_tables:
        if table.name not in _PHASE_TWO_TABLES:
            table.create(bind=bind, checkfirst=True)


def downgrade() -> None:
    bind = op.get_bind()
    for table in reversed(Base.metadata.sorted_tables):
        if table.name not in _PHASE_TWO_TABLES:
            table.drop(bind=bind, checkfirst=True)
