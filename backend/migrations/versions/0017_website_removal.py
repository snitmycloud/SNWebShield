"""Phase 1 addition: owners can remove a website.

* `websites.removed_at`: set when the owner removes the website. The row is kept (past scans, execution events
  and audit records reference it), but it no longer counts toward the plan or appears in the owner's account.
* The "one website per owner and domain" rule becomes a partial unique index that only covers websites that are
  not removed, so a removed domain can be added again. Existing rows are untouched (all have removed_at NULL).

Back up first: python -m app.cli.backup_database. Downgrade is refused.
"""
from alembic import op
import sqlalchemy as sa

revision = "0017_website_removal"
down_revision = "0016_self_service"
branch_labels = None
depends_on = None

TZ = sa.DateTime(timezone=True)


def upgrade():
    with op.batch_alter_table("websites", recreate="always") as batch:
        batch.add_column(sa.Column("removed_at", TZ, nullable=True))
        batch.drop_constraint("uq_website_owner_domain", type_="unique")
    op.create_index("uq_website_owner_domain_active", "websites", ["owner_id", "domain"], unique=True,
                    sqlite_where=sa.text("removed_at IS NULL"), postgresql_where=sa.text("removed_at IS NULL"))


def downgrade():
    raise RuntimeError("Preserve website and scan history; restore a reviewed backup/code pair")
