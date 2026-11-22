"""Preserve legacy windows and require their dates to be re-established."""
from alembic import op
import sqlalchemy as sa

revision = "0002_authorization_utc"
down_revision = "0001_foundation"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("website_authorizations", sa.Column(
        "timestamps_verified", sa.Boolean(), nullable=False, server_default=sa.false()
    ))


def downgrade():
    raise RuntimeError("Downgrade would discard date provenance; restore a reviewed backup instead")
