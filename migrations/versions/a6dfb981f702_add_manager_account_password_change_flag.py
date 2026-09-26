"""Add must_change_password column to users

Revision ID: a6dfb981f702
Revises: 4338b3b37dd5
Create Date: 2026-09-26 18:51:19.319022

"""
from alembic import op
import sqlalchemy as sa


revision = 'a6dfb981f702'
down_revision = '4338b3b37dd5'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.add_column(
            sa.Column(
                'must_change_password',
                sa.Boolean(),
                nullable=False,
                server_default=sa.text('0'),
            )
        )


def downgrade():
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.drop_column('must_change_password')
