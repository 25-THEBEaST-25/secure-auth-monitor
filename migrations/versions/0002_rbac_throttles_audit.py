"""roles, token versions, persistent throttles and security event log

Revision ID: 0002
Revises: 0001
"""
import sqlalchemy as sa
from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("users") as batch:
        # is_locked meant "disabled by an admin"; the new name stops it being
        # confused with the automatic temporary lockout.
        batch.alter_column("is_locked", new_column_name="is_disabled",
                           existing_type=sa.Boolean(), nullable=False, server_default="0")
        batch.add_column(sa.Column("role", sa.String(16), nullable=False, server_default="user"))
        batch.add_column(sa.Column("token_version", sa.Integer(), nullable=False, server_default="0"))
        batch.add_column(sa.Column("created_at", sa.DateTime(timezone=True), nullable=True))

    op.create_table(
        "throttles",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("kind", sa.String(16), nullable=False),
        sa.Column("key", sa.String(255), nullable=False),
        sa.Column("failures", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("window_start", sa.Float(), nullable=False, server_default="0"),
        sa.Column("blocked_until", sa.Float(), nullable=True),
        sa.Column("permanent", sa.Boolean(), nullable=False, server_default="0"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("kind", "key", name="uq_throttles_kind_key"),
    )

    op.create_table(
        "security_events",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("event", sa.String(32), nullable=False),
        sa.Column("username", sa.String(255), nullable=True),
        sa.Column("ip", sa.String(64), nullable=True),
        sa.Column("detail", sa.String(255), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    for column in ("created_at", "event", "username", "ip"):
        op.create_index(f"ix_security_events_{column}", "security_events", [column])


def downgrade():
    for column in ("created_at", "event", "username", "ip"):
        op.drop_index(f"ix_security_events_{column}", table_name="security_events")
    op.drop_table("security_events")
    op.drop_table("throttles")
    with op.batch_alter_table("users") as batch:
        batch.drop_column("created_at")
        batch.drop_column("token_version")
        batch.drop_column("role")
        batch.alter_column("is_disabled", new_column_name="is_locked",
                           existing_type=sa.Boolean(), nullable=True, server_default=None)
