"""Creation of tables

Revision ID: 20d23123c183
Revises: 
Create Date: 2023-03-09 19:58:11.143014

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "20d23123c183"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("public_key", sa.String(), nullable=False),
        sa.Column("verifying_key", sa.String(), nullable=False),
        sa.Column("time_last_challenge", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "time_created",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=True,
        ),
        sa.Column("time_updated", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "items",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("encrypted_data", sa.String(), nullable=False),
        sa.Column("cfrag", sa.String(), nullable=True),
        sa.Column("sender_pkey", sa.String(), nullable=True),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    # ### end Alembic commands ###


def downgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table("items")
    op.drop_table("users")
    # ### end Alembic commands ###