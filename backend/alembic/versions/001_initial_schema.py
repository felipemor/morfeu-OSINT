"""initial schema

Revision ID: 001
Revises: None
Create Date: 2024-01-01
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID, JSON

revision = '001'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Users
    op.create_table('users',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('email', sa.String(255), unique=True, nullable=False),
        sa.Column('hashed_password', sa.String(255), nullable=False),
        sa.Column('full_name', sa.String(255), nullable=False),
        sa.Column('role', sa.String(20), nullable=False, server_default='ANALYST'),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column('last_login', sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index('ix_users_email', 'users', ['email'])

    # Projects
    op.create_table('projects',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('client', sa.String(255), nullable=True),
        sa.Column('business_unit', sa.String(255), nullable=True),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('owner_id', sa.String(36), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('status', sa.String(20), nullable=False, server_default='DRAFT'),
        sa.Column('start_date', sa.DateTime(timezone=True), nullable=True),
        sa.Column('end_date', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # Scopes
    op.create_table('scopes',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('project_id', sa.String(36), sa.ForeignKey('projects.id'), nullable=False, unique=True),
        sa.Column('allowed_domains', JSON, nullable=False, server_default='[]'),
        sa.Column('allowed_ips', JSON, nullable=False, server_default='[]'),
        sa.Column('allowed_cidrs', JSON, nullable=False, server_default='[]'),
        sa.Column('allowed_urls', JSON, nullable=False, server_default='[]'),
        sa.Column('excluded_domains', JSON, nullable=False, server_default='[]'),
        sa.Column('excluded_ips', JSON, nullable=False, server_default='[]'),
        sa.Column('excluded_paths', JSON, nullable=False, server_default='[]'),
        sa.Column('max_requests_per_minute', sa.Integer(), nullable=False, server_default='30'),
        sa.Column('max_concurrent_requests', sa.Integer(), nullable=False, server_default='5'),
        sa.Column('execution_window_start', sa.String(50), nullable=True),
        sa.Column('execution_window_end', sa.String(50), nullable=True),
        sa.Column('authorization_confirmed', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('authorized_by', sa.String(255), nullable=True),
        sa.Column('authorization_document', sa.Text(), nullable=True),
        sa.Column('allow_private_ips', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('scan_mode', sa.String(30), nullable=False, server_default='PASSIVE'),
        sa.Column('notes', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # Credentials
    op.create_table('credentials',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('scope_id', sa.String(36), sa.ForeignKey('scopes.id'), nullable=False),
        sa.Column('label', sa.String(255), nullable=False),
        sa.Column('username', sa.String(255), nullable=True),
        sa.Column('encrypted_password', sa.Text(), nullable=True),
        sa.Column('token_type', sa.String(50), nullable=True),
        sa.Column('encrypted_token', sa.Text(), nullable=True),
        sa.Column('target_domain', sa.String(255), nullable=True),
        sa.Column('notes', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # Targets
    op.create_table('targets',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('project_id', sa.String(36), sa.ForeignKey('projects.id'), nullable=False),
        sa.Column('value', sa.String(512), nullable=False),
        sa.Column('target_type', sa.String(20), nullable=False),
        sa.Column('business_criticality', sa.Integer(), nullable=False, server_default='2'),
        sa.Column('is_internet_facing', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('notes', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # Assets
    op.create_table('assets',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('project_id', sa.String(36), sa.ForeignKey('projects.id'), nullable=False),
        sa.Column('target_id', sa.String(36), sa.ForeignKey('targets.id'), nullable=True),
        sa.Column('asset_type', sa.String(20), nullable=False),
        sa.Column('value', sa.String(512), nullable=False),
        sa.Column('ip_address', sa.String(64), nullable=True),
        sa.Column('port', sa.Integer(), nullable=True),
        sa.Column('protocol', sa.String(10), nullable=True),
        sa.Column('status_code', sa.Integer(), nullable=True),
        sa.Column('title', sa.String(512), nullable=True),
        sa.Column('server', sa.String(255), nullable=True),
        sa.Column('technologies', JSON, nullable=False, server_default='[]'),
        sa.Column('is_internet_facing', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('business_criticality', sa.Integer(), nullable=False, server_default='2'),
        sa.Column('raw_headers', JSON, nullable=True),
        sa.Column('screenshot_path', sa.String(512), nullable=True),
        sa.Column('discovered_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # Endpoints
    op.create_table('endpoints',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('asset_id', sa.String(36), sa.ForeignKey('assets.id'), nullable=False),
        sa.Column('project_id', sa.String(36), sa.ForeignKey('projects.id'), nullable=False),
        sa.Column('url', sa.String(2048), nullable=False),
        sa.Column('method', sa.String(10), nullable=False, server_default='GET'),
        sa.Column('path', sa.String(1024), nullable=False),
        sa.Column('parameters', JSON, nullable=False, server_default='[]'),
        sa.Column('headers', JSON, nullable=False, server_default='{}'),
        sa.Column('auth_required', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('auth_type', sa.String(50), nullable=True),
        sa.Column('content_type', sa.String(100), nullable=True),
        sa.Column('status_code', sa.Integer(), nullable=True),
        sa.Column('is_api', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('source', sa.String(50), nullable=True),
        sa.Column('discovered_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # Scans
    op.create_table('scans',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('project_id', sa.String(36), sa.ForeignKey('projects.id'), nullable=False),
        sa.Column('mode', sa.String(30), nullable=False),
        sa.Column('status', sa.String(20), nullable=False, server_default='PENDING'),
        sa.Column('initiated_by', sa.String(36), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('celery_task_id', sa.String(255), nullable=True),
        sa.Column('progress', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('current_phase', sa.String(100), nullable=True),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('assets_discovered', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('endpoints_found', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('findings_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('killed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # Agent Logs
    op.create_table('agent_logs',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('scan_id', sa.String(36), sa.ForeignKey('scans.id'), nullable=False),
        sa.Column('agent_type', sa.String(30), nullable=False),
        sa.Column('level', sa.String(10), nullable=False, server_default='INFO'),
        sa.Column('message', sa.Text(), nullable=False),
        sa.Column('target', sa.String(512), nullable=True),
        sa.Column('extra_data', JSON, nullable=True),
        sa.Column('timestamp', sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # Findings
    op.create_table('findings',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('project_id', sa.String(36), sa.ForeignKey('projects.id'), nullable=False),
        sa.Column('scan_id', sa.String(36), sa.ForeignKey('scans.id'), nullable=True),
        sa.Column('endpoint_id', sa.String(36), sa.ForeignKey('endpoints.id'), nullable=True),
        sa.Column('asset_id', sa.String(36), sa.ForeignKey('assets.id'), nullable=True),
        sa.Column('title', sa.String(512), nullable=False),
        sa.Column('severity', sa.String(20), nullable=False),
        sa.Column('status', sa.String(30), nullable=False, server_default='OPEN'),
        sa.Column('owasp_category', sa.String(100), nullable=True),
        sa.Column('cwe_id', sa.String(20), nullable=True),
        sa.Column('cvss_score', sa.Float(), nullable=True),
        sa.Column('cvss_vector', sa.String(200), nullable=True),
        sa.Column('confidence', sa.Integer(), nullable=False, server_default='50'),
        sa.Column('risk_score', sa.Float(), nullable=True),
        sa.Column('affected_url', sa.String(2048), nullable=True),
        sa.Column('affected_asset', sa.String(512), nullable=True),
        sa.Column('parameter', sa.String(255), nullable=True),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('business_impact', sa.Text(), nullable=True),
        sa.Column('technical_impact', sa.Text(), nullable=True),
        sa.Column('root_cause', sa.Text(), nullable=True),
        sa.Column('steps_to_reproduce', sa.Text(), nullable=True),
        sa.Column('recommendation', sa.Text(), nullable=True),
        sa.Column('developer_recommendation', sa.Text(), nullable=True),
        sa.Column('architecture_recommendation', sa.Text(), nullable=True),
        sa.Column('compensating_controls', sa.Text(), nullable=True),
        sa.Column('references', JSON, nullable=False, server_default='[]'),
        sa.Column('discovered_by', sa.String(50), nullable=True),
        sa.Column('is_false_positive', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('false_positive_reason', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # Evidence
    op.create_table('evidence',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('finding_id', sa.String(36), sa.ForeignKey('findings.id'), nullable=False),
        sa.Column('scan_id', sa.String(36), sa.ForeignKey('scans.id'), nullable=True),
        sa.Column('http_method', sa.String(10), nullable=True),
        sa.Column('url', sa.String(2048), nullable=True),
        sa.Column('request_headers', sa.Text(), nullable=True),
        sa.Column('request_body', sa.Text(), nullable=True),
        sa.Column('response_status', sa.Integer(), nullable=True),
        sa.Column('response_headers', sa.Text(), nullable=True),
        sa.Column('response_body', sa.Text(), nullable=True),
        sa.Column('screenshot_path', sa.String(512), nullable=True),
        sa.Column('screenshot_url', sa.String(512), nullable=True),
        sa.Column('dom_snapshot', sa.Text(), nullable=True),
        sa.Column('additional_data', JSON, nullable=True),
        sa.Column('evidence_hash', sa.String(64), nullable=True),
        sa.Column('agent_type', sa.String(50), nullable=True),
        sa.Column('test_executed', sa.String(255), nullable=True),
        sa.Column('collected_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # Screenshots
    op.create_table('screenshots',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('project_id', sa.String(36), sa.ForeignKey('projects.id'), nullable=False),
        sa.Column('finding_id', sa.String(36), sa.ForeignKey('findings.id'), nullable=True),
        sa.Column('asset_id', sa.String(36), sa.ForeignKey('assets.id'), nullable=True),
        sa.Column('file_path', sa.String(512), nullable=False),
        sa.Column('file_name', sa.String(255), nullable=False),
        sa.Column('url', sa.String(2048), nullable=True),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('file_hash', sa.String(64), nullable=True),
        sa.Column('taken_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # Reports
    op.create_table('reports',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('project_id', sa.String(36), sa.ForeignKey('projects.id'), nullable=False),
        sa.Column('report_type', sa.String(20), nullable=False),
        sa.Column('format', sa.String(10), nullable=False),
        sa.Column('title', sa.String(512), nullable=False),
        sa.Column('file_path', sa.String(512), nullable=True),
        sa.Column('file_size', sa.Integer(), nullable=True),
        sa.Column('generated_by', sa.String(36), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('finding_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('status', sa.String(20), nullable=False, server_default='GENERATING'),
        sa.Column('error', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
    )

    # Retests
    op.create_table('retests',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('finding_id', sa.String(36), sa.ForeignKey('findings.id'), nullable=False),
        sa.Column('project_id', sa.String(36), sa.ForeignKey('projects.id'), nullable=False),
        sa.Column('initiated_by', sa.String(36), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('status', sa.String(30), nullable=True),
        sa.Column('scan_status', sa.String(20), nullable=False, server_default='PENDING'),
        sa.Column('notes', sa.Text(), nullable=True),
        sa.Column('evidence_before', sa.String(36), nullable=True),
        sa.Column('evidence_after', sa.String(36), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
    )

    # Audit Logs
    op.create_table('audit_logs',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('user_id', sa.String(36), sa.ForeignKey('users.id'), nullable=True),
        sa.Column('action', sa.String(100), nullable=False),
        sa.Column('resource_type', sa.String(50), nullable=True),
        sa.Column('resource_id', sa.String(36), nullable=True),
        sa.Column('project_id', sa.String(36), nullable=True),
        sa.Column('details', JSON, nullable=True),
        sa.Column('ip_address', sa.String(64), nullable=True),
        sa.Column('user_agent', sa.String(512), nullable=True),
        sa.Column('result', sa.String(20), nullable=False, server_default='SUCCESS'),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('timestamp', sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # Risk Scores
    op.create_table('risk_scores',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('project_id', sa.String(36), sa.ForeignKey('projects.id'), nullable=False, unique=True),
        sa.Column('total_score', sa.Float(), nullable=False, server_default='0'),
        sa.Column('critical_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('high_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('medium_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('low_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('info_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('false_positive_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('coverage_percentage', sa.Float(), nullable=False, server_default='0'),
        sa.Column('exploitability_weight', sa.Float(), nullable=False, server_default='1'),
        sa.Column('impact_weight', sa.Float(), nullable=False, server_default='1'),
        sa.Column('exposure_weight', sa.Float(), nullable=False, server_default='1'),
        sa.Column('asset_criticality_weight', sa.Float(), nullable=False, server_default='1'),
        sa.Column('calculated_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
    )


def downgrade() -> None:
    op.drop_table('risk_scores')
    op.drop_table('audit_logs')
    op.drop_table('retests')
    op.drop_table('reports')
    op.drop_table('screenshots')
    op.drop_table('evidence')
    op.drop_table('findings')
    op.drop_table('agent_logs')
    op.drop_table('scans')
    op.drop_table('endpoints')
    op.drop_table('assets')
    op.drop_table('targets')
    op.drop_table('credentials')
    op.drop_table('scopes')
    op.drop_table('projects')
    op.drop_index('ix_users_email', table_name='users')
    op.drop_table('users')
