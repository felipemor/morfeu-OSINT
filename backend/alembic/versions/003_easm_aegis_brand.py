"""add easm, aegislattice, brand-fraud tables

Revision ID: 003
Revises: 002
Create Date: 2026-09-20
"""
from alembic import op
import sqlalchemy as sa

revision = '003'
down_revision = '002'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # EASM
    op.create_table('easm_scans',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('target', sa.String(500), nullable=False),
        sa.Column('scan_type', sa.String(50), server_default='FULL'),
        sa.Column('status', sa.String(20), server_default='PENDING'),
        sa.Column('summary', sa.JSON(), server_default='{}'),
        sa.Column('threat_score', sa.Float(), server_default='0'),
        sa.Column('assets_found', sa.Integer(), server_default='0'),
        sa.Column('dark_web_hits', sa.Integer(), server_default='0'),
        sa.Column('initiated_by', sa.String(36), sa.ForeignKey('users.id'), nullable=True),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index('ix_easm_scans_target', 'easm_scans', ['target'])
    op.create_index('ix_easm_scans_status', 'easm_scans', ['status'])

    op.create_table('easm_darkweb_hits',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('scan_id', sa.String(36), sa.ForeignKey('easm_scans.id'), nullable=False),
        sa.Column('source', sa.String(100), nullable=False),
        sa.Column('hit_type', sa.String(50), nullable=False),
        sa.Column('data_summary', sa.Text(), nullable=True),
        sa.Column('raw_data', sa.JSON(), server_default='{}'),
        sa.Column('severity', sa.String(20), server_default='HIGH'),
        sa.Column('url', sa.String(1000), nullable=True),
        sa.Column('discovered_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index('ix_easm_darkweb_hits_scan_id', 'easm_darkweb_hits', ['scan_id'])

    # AegisLattice
    op.create_table('aegis_scan_results',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('host', sa.String(500), nullable=False),
        sa.Column('port', sa.Integer(), server_default='443'),
        sa.Column('tls_version', sa.String(20), nullable=True),
        sa.Column('cipher_suite', sa.String(200), nullable=True),
        sa.Column('key_exchange', sa.String(100), nullable=True),
        sa.Column('cert_algo', sa.String(100), nullable=True),
        sa.Column('cert_key_bits', sa.Integer(), nullable=True),
        sa.Column('cert_not_after', sa.DateTime(timezone=True), nullable=True),
        sa.Column('risk_level', sa.String(30), server_default='UNKNOWN'),
        sa.Column('risk_score', sa.Float(), server_default='0'),
        sa.Column('cbom', sa.JSON(), server_default='{}'),
        sa.Column('pqc_supported', sa.Boolean(), server_default='false'),
        sa.Column('remediation', sa.Text(), nullable=True),
        sa.Column('scanned_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column('initiated_by', sa.String(36), sa.ForeignKey('users.id'), nullable=True),
    )
    op.create_index('ix_aegis_scan_results_host', 'aegis_scan_results', ['host'])
    op.create_index('ix_aegis_scan_results_risk', 'aegis_scan_results', ['risk_level'])

    # Brand Protection
    op.create_table('brand_alerts',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('brand', sa.String(255), nullable=False),
        sa.Column('suspicious_domain', sa.String(500), nullable=False),
        sa.Column('alert_type', sa.String(30), nullable=False),
        sa.Column('similarity_score', sa.Float(), server_default='0'),
        sa.Column('screenshot_url', sa.String(500), nullable=True),
        sa.Column('registrar', sa.String(255), nullable=True),
        sa.Column('registered_at', sa.String(50), nullable=True),
        sa.Column('ip_address', sa.String(50), nullable=True),
        sa.Column('hosting_provider', sa.String(255), nullable=True),
        sa.Column('status', sa.String(20), server_default='OPEN'),
        sa.Column('takedown_sent_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('evidence', sa.JSON(), server_default='{}'),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index('ix_brand_alerts_brand', 'brand_alerts', ['brand'])
    op.create_index('ix_brand_alerts_status', 'brand_alerts', ['status'])

    # Boleto
    op.create_table('boleto_checks',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('linha_digitavel', sa.String(500), nullable=False),
        sa.Column('bank_code', sa.String(10), nullable=True),
        sa.Column('bank_name', sa.String(200), nullable=True),
        sa.Column('beneficiary_name', sa.String(500), nullable=True),
        sa.Column('beneficiary_cnpj', sa.String(20), nullable=True),
        sa.Column('amount', sa.Float(), nullable=True),
        sa.Column('due_date', sa.String(20), nullable=True),
        sa.Column('is_valid', sa.Boolean(), server_default='true'),
        sa.Column('is_suspicious', sa.Boolean(), server_default='false'),
        sa.Column('fraud_indicators', sa.JSON(), server_default='[]'),
        sa.Column('verdict', sa.String(20), server_default='OK'),
        sa.Column('checked_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column('checked_by', sa.String(36), sa.ForeignKey('users.id'), nullable=True),
    )

    # BIN Incidents
    op.create_table('bin_incidents',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('bin_prefix', sa.String(8), nullable=False),
        sa.Column('bank_name', sa.String(200), nullable=True),
        sa.Column('card_brand', sa.String(50), nullable=True),
        sa.Column('attempts_per_minute', sa.Float(), server_default='0'),
        sa.Column('decline_rate', sa.Float(), server_default='0'),
        sa.Column('source_ips', sa.JSON(), server_default='[]'),
        sa.Column('merchants_affected', sa.JSON(), server_default='[]'),
        sa.Column('severity', sa.String(20), server_default='HIGH'),
        sa.Column('is_active', sa.Boolean(), server_default='true'),
        sa.Column('mitigation_applied', sa.String(50), server_default='NONE'),
        sa.Column('detected_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column('resolved_at', sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index('ix_bin_incidents_bin_prefix', 'bin_incidents', ['bin_prefix'])
    op.create_index('ix_bin_incidents_active', 'bin_incidents', ['is_active'])


def downgrade() -> None:
    op.drop_table('bin_incidents')
    op.drop_table('boleto_checks')
    op.drop_table('brand_alerts')
    op.drop_table('aegis_scan_results')
    op.drop_table('easm_darkweb_hits')
    op.drop_table('easm_scans')
