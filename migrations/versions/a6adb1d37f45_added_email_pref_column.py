"""added email_pref column

Revision ID: a6adb1d37f45
Revises: 195dfc10bbe6
Create Date: 2021-12-08 11:03:20.550212

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'a6adb1d37f45'
down_revision = '195dfc10bbe6'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('clients', sa.Column('mail_pref', sa.Boolean(), nullable=True))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('clients', 'mail_pref')
    # ### end Alembic commands ###