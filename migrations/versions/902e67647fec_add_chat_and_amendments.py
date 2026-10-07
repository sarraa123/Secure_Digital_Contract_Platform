"""add chat and amendments

Revision ID: 902e67647fec
Revises: 875d0fd09a9b
Create Date: 2026-09-30

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '902e67647fec'
down_revision = '875d0fd09a9b'
branch_labels = None
depends_on = None


def upgrade():
    # ---------------------------------------------------------------
    # 1. Ajouter les colonnes à `contracts`
    # ---------------------------------------------------------------
    with op.batch_alter_table('contracts', schema=None) as batch_op:
        batch_op.add_column(
            sa.Column('parent_contract_id', sa.Integer(), nullable=True)
        )
        batch_op.add_column(
            sa.Column('is_amendment', sa.Boolean(), nullable=False,
                      server_default=sa.text('0'))
        )

    # Créer l'index sur parent_contract_id
    with op.batch_alter_table('contracts', schema=None) as batch_op:
        batch_op.create_index(
            'ix_contracts_parent_contract_id',
            ['parent_contract_id'],
            unique=False,
        )

    # ---------------------------------------------------------------
    # 2. Créer la table `contract_messages`
    # ---------------------------------------------------------------
    op.create_table(
        'contract_messages',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('contract_id', sa.Integer(), nullable=False),
        sa.Column('sender_id', sa.Integer(), nullable=True),
        sa.Column('sender_role', sa.String(length=20), nullable=False),
        sa.Column('encrypted_content', sa.LargeBinary(), nullable=False),
        sa.Column('message_type', sa.String(length=20), nullable=False,
                  server_default='text'),
        sa.Column('read_by', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['contract_id'], ['contracts.id'],
                                name='fk_contract_messages_contract'),
        sa.ForeignKeyConstraint(['sender_id'], ['users.id'],
                                name='fk_contract_messages_sender'),
        sa.PrimaryKeyConstraint('id'),
    )
    with op.batch_alter_table('contract_messages', schema=None) as batch_op:
        batch_op.create_index('ix_contract_messages_contract_id',
                              ['contract_id'], unique=False)
        batch_op.create_index('ix_contract_messages_created_at',
                              ['created_at'], unique=False)

    # ---------------------------------------------------------------
    # 3. Créer la table `amendment_requests`
    # ---------------------------------------------------------------
    op.create_table(
        'amendment_requests',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('original_contract_id', sa.Integer(), nullable=False),
        sa.Column('amendment_contract_id', sa.Integer(), nullable=True),
        sa.Column('requested_by', sa.Integer(), nullable=False),
        sa.Column('status', sa.String(length=20), nullable=False,
                  server_default='PENDING'),
        sa.Column('encrypted_summary', sa.LargeBinary(), nullable=True),
        sa.Column('encrypted_modifications', sa.LargeBinary(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('resolved_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['original_contract_id'], ['contracts.id'],
                                name='fk_amendment_original_contract'),
        sa.ForeignKeyConstraint(['amendment_contract_id'], ['contracts.id'],
                                name='fk_amendment_contract'),
        sa.ForeignKeyConstraint(['requested_by'], ['users.id'],
                                name='fk_amendment_requester'),
        sa.PrimaryKeyConstraint('id'),
    )
    with op.batch_alter_table('amendment_requests', schema=None) as batch_op:
        batch_op.create_index('ix_amendment_requests_original_contract_id',
                              ['original_contract_id'], unique=False)
        batch_op.create_index('ix_amendment_requests_amendment_contract_id',
                              ['amendment_contract_id'], unique=False)
        batch_op.create_index('ix_amendment_requests_created_at',
                              ['created_at'], unique=False)


def downgrade():
    # ---------------------------------------------------------------
    # 1. Supprimer `amendment_requests`
    # ---------------------------------------------------------------
    with op.batch_alter_table('amendment_requests', schema=None) as batch_op:
        batch_op.drop_index('ix_amendment_requests_created_at')
        batch_op.drop_index('ix_amendment_requests_amendment_contract_id')
        batch_op.drop_index('ix_amendment_requests_original_contract_id')
    op.drop_table('amendment_requests')

    # ---------------------------------------------------------------
    # 2. Supprimer `contract_messages`
    # ---------------------------------------------------------------
    with op.batch_alter_table('contract_messages', schema=None) as batch_op:
        batch_op.drop_index('ix_contract_messages_created_at')
        batch_op.drop_index('ix_contract_messages_contract_id')
    op.drop_table('contract_messages')

    # ---------------------------------------------------------------
    # 3. Retirer les colonnes de `contracts`
    # ---------------------------------------------------------------
    with op.batch_alter_table('contracts', schema=None) as batch_op:
        batch_op.drop_index('ix_contracts_parent_contract_id')
        batch_op.drop_column('is_amendment')
        batch_op.drop_column('parent_contract_id')