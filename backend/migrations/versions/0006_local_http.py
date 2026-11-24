"""Local Python HTTP assessments and private reports; preserve all prior data."""
from alembic import op
import sqlalchemy as sa
revision="0006_local_http"
down_revision="0005_assessment_intents"
branch_labels=None
depends_on=None

def upgrade():
    op.add_column("assessment_requests",sa.Column("execution_snapshot",sa.JSON(),nullable=True))
    op.create_table("assessment_reports",
        sa.Column("id",sa.String(36),primary_key=True),
        sa.Column("assessment_id",sa.String(36),sa.ForeignKey("assessment_requests.id",ondelete="RESTRICT"),nullable=False,unique=True),
        sa.Column("created_at",sa.DateTime(timezone=True),nullable=False),
        sa.Column("content",sa.JSON(),nullable=False),sa.Column("sha256",sa.String(64),nullable=False),
        sa.Column("size",sa.Integer(),nullable=False))

def downgrade():
    raise RuntimeError("Preserve assessment reports; restore a reviewed backup/code pair")
