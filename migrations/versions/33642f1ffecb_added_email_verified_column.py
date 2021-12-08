"""added email_verified column

Revision ID: 33642f1ffecb
Revises: ccd6a412b1f6
Create Date: 2021-11-22 14:14:46.460760

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '33642f1ffecb'
down_revision = 'ccd6a412b1f6'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('clients', sa.Column('verified', sa.Boolean(), nullable=True))
    op.add_column('investment_fund', sa.Column('todays_price', sa.Float(), nullable=True))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('investment_fund', 'todays_price')
    op.drop_column('clients', 'verified')
    # ### end Alembic commands ###