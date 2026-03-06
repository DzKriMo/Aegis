"""users and session owner

Revision ID: 0002_users_and_session_owner
Revises: 0001_initial
Create Date: 2026-03-05
"""

from alembic import op
import sqlalchemy as sa

revision = "0002_users_and_session_owner"
down_revision = "0001_initial"
branch_labels = None
depends_on = None


def upgrade():
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    tables = set(inspector.get_table_names())

    if "aegis_users" not in tables:
        op.create_table(
            "aegis_users",
            sa.Column("id", sa.Integer, primary_key=True),
            sa.Column("tenant_id", sa.Integer, nullable=True),
            sa.Column("username", sa.String(length=64), nullable=False, unique=True),
            sa.Column("display_name", sa.String(length=128), nullable=True),
            sa.Column("role", sa.String(length=32), nullable=False, server_default="employee"),
            sa.Column("active", sa.Boolean, nullable=False, server_default=sa.true()),
        )

    if "aegis_sessions" in tables:
        session_columns = {col["name"] for col in inspector.get_columns("aegis_sessions")}
        if "user_id" not in session_columns:
            op.add_column("aegis_sessions", sa.Column("user_id", sa.Integer, nullable=True))
        if "username" not in session_columns:
            op.add_column("aegis_sessions", sa.Column("username", sa.String(length=64), nullable=True))


def downgrade():
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    tables = set(inspector.get_table_names())

    if "aegis_sessions" in tables:
        session_columns = {col["name"] for col in inspector.get_columns("aegis_sessions")}
        if "username" in session_columns:
            op.drop_column("aegis_sessions", "username")
        if "user_id" in session_columns:
            op.drop_column("aegis_sessions", "user_id")

    if "aegis_users" in tables:
        op.drop_table("aegis_users")
