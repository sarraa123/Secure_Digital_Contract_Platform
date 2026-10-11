"""merge contracts (chat/amendments) and sarra-security (MFA)

Revision ID: a9244514ef95
Revises: 21d82f704a61, 902e67647fec
Create Date: 2026-10-06 21:43:37.620358

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'a9244514ef95'
down_revision = ('21d82f704a61', '902e67647fec')
branch_labels = None
depends_on = None


def upgrade():
    pass


def downgrade():
    pass
