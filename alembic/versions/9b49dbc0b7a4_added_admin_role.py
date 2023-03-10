"""Added admin role

Revision ID: 9b49dbc0b7a4
Revises: 20d23123c183
Create Date: 2023-03-10 16:45:06.294439

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "9b49dbc0b7a4"
down_revision = "20d23123c183"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column("users", sa.Column("admin", sa.Boolean(), nullable=False))
    # ### end Alembic commands ###


def downgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column("users", "admin")
    # ### end Alembic commands ###