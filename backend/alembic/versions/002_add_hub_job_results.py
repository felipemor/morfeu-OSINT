"""add hub_job_results table

Revision ID: 002
Revises: 001
Create Date: 2026-09-20
"""
from alembic import op
import sqlalchemy as sa

revision = '002'
down_revision = '001'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'hub_job_results',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('category', sa.String(20), nullable=False),
        sa.Column('tool_name', sa.String(100), nullable=False),
        sa.Column('target', sa.String(500), nullable=True),
        sa.Column('params', sa.JSON(), nullable=True, server_default='{}'),
        sa.Column('status', sa.String(20), nullable=False, server_default='PENDING'),
        sa.Column('raw_output', sa.Text(), nullable=True),
        sa.Column('parsed_result', sa.JSON(), nullable=True, server_default='{}'),
        sa.Column('findings_registered', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('initiated_by', sa.String(36), sa.ForeignKey('users.id'), nullable=True),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index('ix_hub_job_results_category', 'hub_job_results', ['category'])
    op.create_index('ix_hub_job_results_status', 'hub_job_results', ['status'])
    op.create_index('ix_hub_job_results_created_at', 'hub_job_results', ['created_at'])


def downgrade() -> None:
    op.drop_index('ix_hub_job_results_created_at', table_name='hub_job_results')
    op.drop_index('ix_hub_job_results_status', table_name='hub_job_results')
    op.drop_index('ix_hub_job_results_category', table_name='hub_job_results')
    op.drop_table('hub_job_results')
