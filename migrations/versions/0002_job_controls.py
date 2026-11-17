"""Job monitor: who started a job, when it started running, and the AI calls / tokens it has used.

Revision ID: 0002_job_controls
Revises: 0001_initial
Create Date: 2026-11-15
"""
from alembic import op

revision = "0002_job_controls"
down_revision = "0001_initial"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        ALTER TABLE jobs
            ADD COLUMN created_by BIGINT REFERENCES users(id) ON DELETE SET NULL,
            ADD COLUMN started_at TEXT NOT NULL DEFAULT '',
            ADD COLUMN ai_calls   INTEGER NOT NULL DEFAULT 0,
            ADD COLUMN ai_tokens  BIGINT NOT NULL DEFAULT 0;
        CREATE INDEX ix_jobs_workspace_status ON jobs (workspace_id, status);
    """)


def downgrade() -> None:
    op.execute("""
        DROP INDEX IF EXISTS ix_jobs_workspace_status;
        ALTER TABLE jobs DROP COLUMN created_by, DROP COLUMN started_at, DROP COLUMN ai_calls, DROP COLUMN ai_tokens;
    """)
