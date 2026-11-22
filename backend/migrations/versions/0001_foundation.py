"""Adopt the five-table foundation, or create it in a new empty database."""
from alembic import op
import sqlalchemy as sa

revision = "0001_foundation"
down_revision = None
branch_labels = None
depends_on = None

# Exact column names from commit 50b0f0e. Refuse partial/unrecognised schemas.
BASELINE_COLUMNS = {'admins': ['created_at', 'email', 'full_name', 'id', 'is_active', 'last_login_at', 'password_hash', 'role', 'updated_at'], 'clients': ['company_name', 'created_at', 'email', 'id', 'industry', 'notes', 'phone', 'primary_contact_name', 'updated_at'], 'websites': ['authorisation_status', 'client_id', 'created_at', 'environment', 'hosting_provider', 'id', 'name', 'notes', 'platform', 'url'], 'website_authorizations': ['authorization_reference', 'authorized_by', 'authorized_domains', 'created_at', 'evidence_storage_key', 'id', 'internal_review_notes', 'permitted_methods', 'status', 'updated_at', 'valid_from', 'valid_until', 'website_id'], 'authorization_audit_events': ['action', 'admin_id', 'authorization_id', 'created_at', 'evidence_reviewed', 'id', 'new_status', 'note', 'previous_status']}

def upgrade():
    inspector = sa.inspect(op.get_bind())
    existing = set(inspector.get_table_names()) - {"alembic_version"}
    if existing:
        if not set(BASELINE_COLUMNS).issubset(existing):
            raise RuntimeError("Partial database schema; stop and review before migration")
        for table, expected in BASELINE_COLUMNS.items():
            actual = {column["name"] for column in inspector.get_columns(table)}
            if actual != set(expected):
                raise RuntimeError("Unexpected schema in " + table + "; stop and review before migration")
        return

    # Frozen schema from the reviewed commit.
    op.create_table('admins',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('email', sa.String(length=320), nullable=False),
    sa.Column('full_name', sa.String(length=150), nullable=False),
    sa.Column('password_hash', sa.String(length=512), nullable=False),
    sa.Column('role', sa.String(length=20), nullable=False),
    sa.Column('is_active', sa.Boolean(), nullable=False),
    sa.Column('last_login_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    sa.CheckConstraint("role IN ('admin')", name='ck_admins_role'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_admins_email'), 'admins', ['email'], unique=True)
    op.create_index(op.f('ix_admins_id'), 'admins', ['id'], unique=False)
    op.create_table('clients',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('company_name', sa.String(length=200), nullable=False),
    sa.Column('primary_contact_name', sa.String(length=150), nullable=False),
    sa.Column('email', sa.String(length=320), nullable=False),
    sa.Column('phone', sa.String(length=40), nullable=True),
    sa.Column('industry', sa.String(length=100), nullable=True),
    sa.Column('notes', sa.Text(), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_clients_company_name'), 'clients', ['company_name'], unique=False)
    op.create_index(op.f('ix_clients_email'), 'clients', ['email'], unique=False)
    op.create_index(op.f('ix_clients_id'), 'clients', ['id'], unique=False)
    op.create_table('websites',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('client_id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=200), nullable=False),
    sa.Column('url', sa.String(length=2048), nullable=False),
    sa.Column('platform', sa.String(length=100), nullable=True),
    sa.Column('environment', sa.String(length=30), nullable=False),
    sa.Column('hosting_provider', sa.String(length=150), nullable=True),
    sa.Column('notes', sa.Text(), nullable=True),
    sa.Column('authorisation_status', sa.String(length=30), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    sa.ForeignKeyConstraint(['client_id'], ['clients.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_websites_client_id'), 'websites', ['client_id'], unique=False)
    op.create_index(op.f('ix_websites_id'), 'websites', ['id'], unique=False)
    op.create_index(op.f('ix_websites_url'), 'websites', ['url'], unique=False)
    op.create_table('website_authorizations',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('website_id', sa.Integer(), nullable=False),
    sa.Column('authorization_reference', sa.String(length=120), nullable=False),
    sa.Column('authorized_by', sa.String(length=150), nullable=False),
    sa.Column('authorized_domains', sa.JSON(), nullable=False),
    sa.Column('permitted_methods', sa.JSON(), nullable=False),
    sa.Column('valid_from', sa.DateTime(timezone=True), nullable=False),
    sa.Column('valid_until', sa.DateTime(timezone=True), nullable=False),
    sa.Column('status', sa.String(length=20), nullable=False),
    sa.Column('evidence_storage_key', sa.String(length=500), nullable=True),
    sa.Column('internal_review_notes', sa.Text(), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    sa.CheckConstraint("status IN ('pending', 'approved', 'rejected', 'expired', 'revoked')", name='ck_website_authorizations_status'),
    sa.ForeignKeyConstraint(['website_id'], ['websites.id'], ondelete='RESTRICT'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_website_authorizations_authorization_reference'), 'website_authorizations', ['authorization_reference'], unique=False)
    op.create_index(op.f('ix_website_authorizations_id'), 'website_authorizations', ['id'], unique=False)
    op.create_index(op.f('ix_website_authorizations_status'), 'website_authorizations', ['status'], unique=False)
    op.create_index(op.f('ix_website_authorizations_website_id'), 'website_authorizations', ['website_id'], unique=False)
    op.create_table('authorization_audit_events',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('authorization_id', sa.Integer(), nullable=False),
    sa.Column('admin_id', sa.Integer(), nullable=False),
    sa.Column('action', sa.String(length=20), nullable=False),
    sa.Column('previous_status', sa.String(length=20), nullable=False),
    sa.Column('new_status', sa.String(length=20), nullable=False),
    sa.Column('note', sa.Text(), nullable=False),
    sa.Column('evidence_reviewed', sa.Boolean(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    sa.CheckConstraint("action IN ('approved', 'rejected', 'revoked')", name='ck_authorization_audit_events_action'),
    sa.CheckConstraint("new_status IN ('approved', 'rejected', 'revoked')", name='ck_authorization_audit_events_new_status'),
    sa.CheckConstraint("previous_status IN ('pending', 'approved')", name='ck_authorization_audit_events_previous_status'),
    sa.ForeignKeyConstraint(['admin_id'], ['admins.id'], ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['authorization_id'], ['website_authorizations.id'], ondelete='RESTRICT'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_authorization_audit_events_admin_id'), 'authorization_audit_events', ['admin_id'], unique=False)
    op.create_index(op.f('ix_authorization_audit_events_authorization_id'), 'authorization_audit_events', ['authorization_id'], unique=False)
    op.create_index(op.f('ix_authorization_audit_events_id'), 'authorization_audit_events', ['id'], unique=False)



def downgrade():
    raise RuntimeError("This baseline adoption cannot be downgraded destructively. Restore a reviewed backup instead.")
