"""Store PSK encrypted in DB, remove S3 dependency.

Makes psk_secret_name nullable (previously pointed to S3 object key; no longer used).
Adds psk_encrypted column to hold the KMS-encrypted PSK ciphertext (base64).

Revision ID: 0013
Revises: 0012
Create Date: 2026-10-21

"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0013"
down_revision: Union[str, None] = "0012"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Allow existing rows to have a null psk_secret_name (S3 path no longer required).
    op.alter_column("tunnels", "psk_secret_name", nullable=True)

    # Add column for KMS-encrypted PSK ciphertext (base64-encoded).
    op.add_column(
        "tunnels",
        sa.Column("psk_encrypted", sa.Text(), nullable=True),
    )


def downgrade() -> None:
    # Remove the encrypted PSK column.
    op.drop_column("tunnels", "psk_encrypted")

    # Restore NOT NULL on psk_secret_name.
    # NOTE: rows with NULL psk_secret_name will cause this to fail unless
    # they are backfilled first. In dev the DB is recreated, so this is safe.
    op.alter_column("tunnels", "psk_secret_name", nullable=False)
