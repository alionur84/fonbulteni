"""yochanged password field 

Revision ID: 32e13798cc69
Revises: 
Create Date: 2021-10-18 21:26:14.666742

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '32e13798cc69'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('clients', sa.Column('password_hash', sa.String(length=128), nullable=True))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('clients', 'password_hash')
    # ### end Alembic commands ###
