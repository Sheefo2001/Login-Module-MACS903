"""create users table

Revision ID: 001_create_users_table
Revises:
Create Date: 2026-02-09
"""

from alembic import op
import sqlalchemy as sa

revision = "001_create_users_table"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "users",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("username", sa.String(length=255), nullable=False, unique=True),
        sa.Column("insecure_password_plain", sa.Text, nullable=True),
        sa.Column("insecure_password_md5", sa.String(length=32), nullable=True),
        sa.Column("secure_password_hash", sa.Text, nullable=False),
    )


def downgrade():
    op.drop_table("users")
