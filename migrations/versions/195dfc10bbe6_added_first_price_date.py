"""added first_price & date

Revision ID: 195dfc10bbe6
Revises: 208b00cd327f
Create Date: 2021-11-25 13:19:49.146528

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '195dfc10bbe6'
down_revision = '208b00cd327f'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('investment_fund', sa.Column('first_price', sa.Float(), nullable=True))
    op.add_column('investment_fund', sa.Column('first_price_date', sa.DateTime(), nullable=True))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('investment_fund', 'first_price_date')
    op.drop_column('investment_fund', 'first_price')
    # ### end Alembic commands ###