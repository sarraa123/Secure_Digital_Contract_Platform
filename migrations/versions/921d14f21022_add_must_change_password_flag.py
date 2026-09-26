"""Add must change password flag (no-op, deja fait par a6dfb981f702)

Revision ID: 921d14f21022
Revises: a6dfb981f702
Create Date: 2026-09-26 19:02:00.624710

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '921d14f21022'
down_revision = 'a6dfb981f702'
branch_labels = None
depends_on = None


def upgrade():
    # Deja fait par la migration a6dfb981f702.
    # Cette migration est conservee uniquement pour ne pas casser la chaine.
    pass


def downgrade():
    # Rien a faire : la colonne appartient a a6dfb981f702.
    pass