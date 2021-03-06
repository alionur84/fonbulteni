"""added username

Revision ID: 7703a899580c
Revises: 32e13798cc69
Create Date: 2021-10-19 13:55:06.304623

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '7703a899580c'
down_revision = '32e13798cc69'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('clients', sa.Column('username', sa.String(length=20), nullable=False))
    op.create_unique_constraint(None, 'clients', ['username'])
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_constraint(None, 'clients', type_='unique')
    op.drop_column('clients', 'username')
    # ### end Alembic commands ###
