"""
Unit Tests for Endpoint Security Assessment Agent & Baseline Drift Engine
"""
import pytest
import asyncio
from app.checks.endpoint.base import EndpointCheckContext
from app.checks.endpoint.firewall.firewall_check import FirewallAssessmentCheck
from app.checks.endpoint.services.services_check import ServiceAssessmentCheck
from app.checks.endpoint.security_controls.controls_check import SecurityControlsCheck
from app.checks.endpoint.os.os_check import OsAssessmentCheck
from app.checks.endpoint.patch.patch_check import PatchAssessmentCheck
from app.checks.endpoint.registry import endpoint_check_registry
from app.services.baseline_drift_service import BaselineDriftService
from app.models import Severity


# ─── 1. Endpoint Checks Unit Tests ──────────────────────────────────────────

def test_firewall_check_disabled():
    async def run():
        check = FirewallAssessmentCheck()
        context = EndpointCheckContext(
            agent_id="agt-1",
            asset_id="ast-1",
            platform="windows",
            hostname="workstation-01",
            telemetry_data={"firewall": {"enabled": False, "profiles": {"domain": False, "private": False, "public": False}}},
        )
        result = await check.evaluate(context)
        assert result.status == "FAIL"
        assert result.severity == Severity.HIGH
        assert "Disabled" in result.title

    asyncio.run(run())


def test_firewall_check_enabled():
    async def run():
        check = FirewallAssessmentCheck()
        context = EndpointCheckContext(
            agent_id="agt-1",
            asset_id="ast-1",
            platform="windows",
            hostname="workstation-01",
            telemetry_data={"firewall": {"enabled": True, "profiles": {"domain": True, "private": True, "public": True}}},
        )
        result = await check.evaluate(context)
        assert result.status == "PASS"
        assert result.severity == Severity.INFO

    asyncio.run(run())


def test_services_check_insecure_ports():
    async def run():
        check = ServiceAssessmentCheck()
        context = EndpointCheckContext(
            agent_id="agt-1",
            asset_id="ast-1",
            platform="linux",
            hostname="server-02",
            telemetry_data={"listening_ports": [22, 23, 80, 513]},  # 23=Telnet, 513=Rlogin
        )
        result = await check.evaluate(context)
        assert result.status == "FAIL"
        assert result.severity == Severity.HIGH
        assert "Legacy / Insecure" in result.title
        assert "23" in str(result.evidence)

    asyncio.run(run())


def test_security_controls_edr_and_encryption():
    async def run():
        check = SecurityControlsCheck()
        # Missing EDR and encryption
        context = EndpointCheckContext(
            agent_id="agt-1",
            asset_id="ast-1",
            platform="windows",
            hostname="laptop-exec",
            telemetry_data={"security_controls": {"edr_active": False, "disk_encrypted": False}},
        )
        result = await check.evaluate(context)
        assert result.status == "FAIL"
        assert result.severity == Severity.HIGH
        assert "Missing Critical Endpoint Security Controls" in result.title

        # Active EDR & encryption
        ok_context = EndpointCheckContext(
            agent_id="agt-1",
            asset_id="ast-1",
            platform="windows",
            hostname="laptop-exec",
            telemetry_data={"security_controls": {"edr_active": True, "disk_encrypted": True, "edr_name": "Defender"}},
        )
        ok_res = await check.evaluate(ok_context)
        assert ok_res.status == "PASS"
        assert ok_res.severity == Severity.INFO

    asyncio.run(run())


def test_os_assessment_check_uac_and_ssh():
    async def run():
        check = OsAssessmentCheck()
        # Windows with UAC disabled
        win_ctx = EndpointCheckContext(
            agent_id="agt-1",
            asset_id="ast-1",
            platform="windows",
            hostname="win-srv",
            telemetry_data={"os": {"uac_enabled": False}},
        )
        res_win = await check.evaluate(win_ctx)
        assert res_win.status == "FAIL"
        assert "UAC" in str(res_win.description)

        # Linux with PermitRootLogin enabled
        lin_ctx = EndpointCheckContext(
            agent_id="agt-2",
            asset_id="ast-2",
            platform="linux",
            hostname="lin-srv",
            telemetry_data={"os": {"permit_root_login": True}},
        )
        res_lin = await check.evaluate(lin_ctx)
        assert res_lin.status == "FAIL"
        assert "SSH root login" in str(res_lin.description)

    asyncio.run(run())


def test_patch_assessment_check():
    async def run():
        check = PatchAssessmentCheck()
        ctx = EndpointCheckContext(
            agent_id="agt-1",
            asset_id="ast-1",
            platform="windows",
            hostname="dc-01",
            telemetry_data={"patches": {"missing_critical_count": 3, "days_since_last_update": 75}},
        )
        result = await check.evaluate(ctx)
        assert result.status == "FAIL"
        assert result.severity == Severity.HIGH
        assert "Missing Critical Security Updates" in result.title

    asyncio.run(run())


# ─── 2. Endpoint Check Registry Tests ────────────────────────────────────────

def test_endpoint_check_registry():
    checks = endpoint_check_registry.list_checks()
    assert len(checks) >= 5
    check_ids = [getattr(c, "id", getattr(c, "check_id", "")) for c in checks]
    assert "EP-FW-001" in check_ids
    assert "EP-SVC-001" in check_ids
    assert "EP-CTL-001" in check_ids
    assert "EP-OS-001" in check_ids
    assert "EP-PATCH-001" in check_ids

    win_checks = endpoint_check_registry.get_checks_for_platform("windows")
    assert len(win_checks) >= 4


# ─── 3. Baseline & Drift Detection Engine Tests ──────────────────────────────

def test_drift_computation_firewall_and_edr():
    service = BaselineDriftService()
    baseline = {
        "firewall_enabled": True,
        "edr_active": True,
        "open_ports": [22, 80, 443],
        "uac_enabled": True,
    }

    # Current state with firewall disabled & EDR killed & new port
    current = {
        "firewall_enabled": False,
        "edr_active": False,
        "open_ports": [22, 80, 443, 8080],
        "uac_enabled": True,
    }

    diff, drift_types, max_severity = service._compute_diff(baseline, current)
    assert "firewall_disabled" in diff
    assert "edr_deactivated" in diff
    assert "new_listening_ports" in diff
    assert diff["new_listening_ports"] == [8080]
    assert "FIREWALL_DISABLED" in drift_types
    assert "EDR_DEACTIVATED" in drift_types
    assert max_severity == Severity.CRITICAL


def test_drift_computation_no_change():
    service = BaselineDriftService()
    baseline = {
        "firewall_enabled": True,
        "edr_active": True,
        "open_ports": [22, 80],
        "uac_enabled": True,
    }
    diff, drift_types, max_severity = service._compute_diff(baseline, baseline)
    assert diff == {}
    assert len(drift_types) == 0


# ─── 4. Cross-Plane Correlation Tests ────────────────────────────────────────

def test_cross_plane_correlation_logic():
    from unittest.mock import AsyncMock, MagicMock
    from app.services.cross_plane_correlation import CrossPlaneCorrelationEngine
    from app.models import Asset, Finding, Severity

    engine = CrossPlaneCorrelationEngine()
    
    # Mock DB session
    mock_db = AsyncMock()
    
    asset = Asset(
        id="ast-101",
        project_id="prj-1",
        value="api.internal.corp",
        hostname="api.internal.corp",
        agent_id="agt-99",
    )
    
    ext_finding = Finding(
        id="f-1",
        project_id="prj-1",
        title="Exposed Swagger UI & Unauthenticated API",
        description="Publicly accessible API documentation without auth",
        affected_asset="api.internal.corp",
        severity=Severity.HIGH,
        agent_id=None,
    )
    
    ep_finding = Finding(
        id="f-2",
        project_id="prj-1",
        title="Endpoint Missing Critical Security Updates",
        description="3 missing critical security patches detected on endpoint",
        affected_asset="api.internal.corp",
        severity=Severity.CRITICAL,
        agent_id="agt-99",
    )

    async def run():
        # First query for assets
        mock_asset_result = MagicMock()
        mock_asset_result.scalars.return_value.all.return_value = [asset]
        
        # Second query for findings
        mock_finding_result = MagicMock()
        mock_finding_result.scalars.return_value.all.return_value = [ext_finding, ep_finding]
        
        mock_db.execute.side_effect = [mock_asset_result, mock_finding_result]
        
        correlations = await engine.correlate_project_assets(mock_db, "prj-1")
        assert len(correlations) == 1
        assert correlations[0]["asset_id"] == "ast-101"
        assert correlations[0]["external_exposure_count"] == 1
        assert correlations[0]["endpoint_weakness_count"] == 1
        assert correlations[0]["correlated_risk_level"] == "CRITICAL"

    asyncio.run(run())


# ─── 5. Cryptographic Integrity & Token Tests ────────────────────────────────

def test_token_hash_and_signature_integrity():
    import secrets
    import hashlib
    import json

    raw_token = f"agt_{secrets.token_urlsafe(32)}"
    assert raw_token.startswith("agt_")
    assert len(raw_token) > 40

    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    assert len(token_hash) == 64

    # Verify task signature determinism
# ─── 6. Security Controls & Audit Trail Tests ────────────────────────────────

def test_security_controls_validation_and_audit_logging():
    from unittest.mock import AsyncMock, MagicMock
    from app.services.security_controls_service import SecurityControlsService, SECURITY_CONTROLS_CATALOG

    service = SecurityControlsService()
    assert len(SECURITY_CONTROLS_CATALOG) == 32

    mock_db = AsyncMock()
    # Mock log query
    mock_result = MagicMock()
    mock_result.scalars.return_value.all.return_value = []
    mock_db.execute.return_value = mock_result

    async def run():
        # Test overview
        overview = await service.get_controls_overview(mock_db)
        assert overview["total_controls"] == 32
        assert len(overview["shield_benefits"]) == 7
        assert overview["posture_score"] == 100.0

        # Test single control validation for external URL (TLS)
        res = await service.execute_control_test(
            db=mock_db,
            control_id="SEC-EXT-01",
            target_value="https://app.shieldsecurity.io",
            user_id="usr-admin",
            project_id="prj-001",
        )
        assert res["status"] == "PASSED"
        assert len(res["evidence_hash"]) == 64
        assert mock_db.commit.called

        # Test Akamai check and leak scan methods
        akamai_info = await service.detect_akamai_waf("https://app.shieldsecurity.io")
        assert "is_akamai_waf" in akamai_info

        leak_info = await service.scan_sensitive_leaks("https://app.shieldsecurity.io")
        assert "leaks_found_count" in leak_info

        sub_info = await service.enumerate_subdomains("shieldsecurity.io")
        assert "subdomains" in sub_info

        # Test PDF generation
        pdf_bytes = await service.generate_pdf_report(
            db=mock_db,
            target_url="https://app.shieldsecurity.io",
            user_id="Admin Auditor",
        )
        assert isinstance(pdf_bytes, bytes)
        assert pdf_bytes.startswith(b"%PDF")

    asyncio.run(run())




