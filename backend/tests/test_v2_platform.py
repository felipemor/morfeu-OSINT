"""
Comprehensive Unit & Security Test Suite for V2 AI Security Reasoning Platform
"""
import pytest
from app.core.scope_validator import ScopeValidator, ScopeViolationError, mask_sensitive_data
from app.security.policy_engine import PolicyEngine, PolicyConfig, PolicyDecision, RateLimiter
from app.security.rbac_abac import AccessControlEngine, Action, AuthContext, UserRole
from app.services.compliance import ComplianceService
from app.services.evidence_service import mask_sensitive_content, compute_evidence_hash
from app.services.finding_pipeline import FindingPipelineService, ALLOWED_TRANSITIONS, InvalidFindingTransitionError
from app.services.risk_engine import calculate_finding_business_risk
from app.models import Severity, BusinessCriticality, FindingStatus


# ─── 1. Scope Validator Tests ──────────────────────────────────────────────────

def test_scope_validator_allowed_domain():
    validator = ScopeValidator(allowed_domains=["example.com"])
    # Exact domain
    validator.validate("example.com")
    # Subdomain
    validator.validate("api.example.com")
    validator.validate("https://staging.api.example.com/v1/users")


def test_scope_validator_excluded_domain_and_path():
    validator = ScopeValidator(
        allowed_domains=["example.com"],
        excluded_domains=["admin.example.com"],
        excluded_paths=["/internal"],
    )
    # Allowed
    validator.validate("https://app.example.com/dashboard")

    # Excluded domain
    with pytest.raises(ScopeViolationError):
        validator.validate("https://admin.example.com/login")

    # Excluded path
    with pytest.raises(ScopeViolationError):
        validator.validate("https://app.example.com/internal/secret")


def test_scope_validator_private_ip_blocking():
    validator = ScopeValidator(allow_private_ips=False)
    with pytest.raises(ScopeViolationError):
        validator.validate("10.0.0.1")
    with pytest.raises(ScopeViolationError):
        validator.validate("192.168.1.50")
    with pytest.raises(ScopeViolationError):
        validator.validate("127.0.0.1")

    # Allow private IPs override
    lab_validator = ScopeValidator(allow_private_ips=True, allowed_ips=["10.0.0.1"])
    lab_validator.validate("10.0.0.1")


# ─── 2. Policy Engine Tests ───────────────────────────────────────────────────

def test_policy_engine_methods_and_paths():
    scope = ScopeValidator(allowed_domains=["example.com"])
    policy = PolicyEngine(
        scope_validator=scope,
        config=PolicyConfig(
            allowed_methods=["GET", "POST"],
            forbidden_paths=["/admin/delete/*"],
            allowed_ports=[80, 443, 8080],
        ),
    )

    # Valid GET request
    res = policy.evaluate_request("https://example.com/api/users", method="GET")
    assert res.allowed is True
    assert res.decision == PolicyDecision.ALLOW

    # Disallowed method
    res_delete = policy.evaluate_request("https://example.com/api/users", method="DELETE")
    assert res_delete.allowed is False
    assert res_delete.policy_rule == "METHOD_NOT_ALLOWED"

    # Forbidden path pattern
    res_forbidden = policy.evaluate_request("https://example.com/admin/delete/user123", method="POST")
    assert res_forbidden.allowed is False
    assert res_forbidden.policy_rule == "PATH_FORBIDDEN"

    # Port restriction
    res_port = policy.evaluate_request("http://example.com:9999/test", method="GET")
    assert res_port.allowed is False
    assert res_port.policy_rule == "PORT_FORBIDDEN"


def test_policy_engine_rate_limiter():
    limiter = RateLimiter()
    key = "test_target"
    max_rpm = 3

    assert limiter.check_and_record(key, max_rpm) is True
    assert limiter.check_and_record(key, max_rpm) is True
    assert limiter.check_and_record(key, max_rpm) is True
    # 4th request exceeds limit
    assert limiter.check_and_record(key, max_rpm) is False


def test_policy_engine_production_human_approval():
    scope = ScopeValidator(allowed_domains=["prod.example.com"])
    policy = PolicyEngine(
        scope_validator=scope,
        config=PolicyConfig(
            environment="production",
            allowed_methods=["GET", "DELETE"],
            require_human_approval_for_destructive=True,
            high_risk_methods=["DELETE"],
        ),
    )
    # In production, DELETE requires human approval
    res = policy.evaluate_request("https://prod.example.com/api/item", method="DELETE")
    assert res.allowed is False
    assert res.decision == PolicyDecision.APPROVAL_REQUIRED


# ─── 3. RBAC & ABAC Engine Tests ──────────────────────────────────────────────

def test_rbac_abac_matrix():
    admin_ctx = AuthContext(user_id="u1", user_role=UserRole.ADMIN)
    assert AccessControlEngine.is_authorized(Action.MANAGE_USERS, admin_ctx)[0] is True
    assert AccessControlEngine.is_authorized(Action.START_SCAN, admin_ctx)[0] is True

    auditor_ctx = AuthContext(user_id="u2", user_role=UserRole.AUDITOR)
    assert AccessControlEngine.is_authorized(Action.VIEW_AUDIT_LOGS, auditor_ctx)[0] is True
    # Auditor cannot start scans or approve actions
    assert AccessControlEngine.is_authorized(Action.START_SCAN, auditor_ctx)[0] is False
    assert AccessControlEngine.is_authorized(Action.APPROVE_AI_ACTION, auditor_ctx)[0] is False


def test_rbac_abac_multitenant_isolation():
    pentester_ctx = AuthContext(
        user_id="u3",
        user_role=UserRole.PENTESTER,
        user_org_id="org-123",
        target_org_id="org-999",  # Cross-organization
    )
    allowed, reason = AccessControlEngine.is_authorized(Action.VIEW_FINDINGS, pentester_ctx)
    assert allowed is False
    assert "Cross-organization" in reason


# ─── 4. Evidence Hashing & Secret Masking Tests ───────────────────────────────

def test_secret_masking():
    raw_header = "Authorization: Bearer secret_jwt_token_12345\npassword = super_secret_pass\napi_key: abc-123"
    masked_header = mask_sensitive_content(raw_header)
    assert "secret_jwt_token_12345" not in masked_header
    assert "[MASKED:AUTH_HEADER]" in masked_header
    assert "super_secret_pass" not in masked_header
    assert "[MASKED:PASSWORD]" in masked_header
    assert "[MASKED:API_KEY]" in masked_header

    # Test standalone bearer token in body or log
    raw_bearer = "Received header with Bearer eyJhbGciOiJIUzI1NiJ9.test in body"
    masked_bearer = mask_sensitive_content(raw_bearer)
    assert "[MASKED:BEARER_TOKEN]" in masked_bearer
    assert "eyJhbGciOiJIUzI1NiJ9" not in masked_bearer




def test_evidence_hash_determinism():
    h1 = compute_evidence_hash("f1", "https://example.com", "GET", 200, "req", "resp", "2026-09-04T00:00:00Z")
    h2 = compute_evidence_hash("f1", "https://example.com", "GET", 200, "req", "resp", "2026-09-04T00:00:00Z")
    h3 = compute_evidence_hash("f1", "https://example.com", "GET", 500, "req", "resp", "2026-09-04T00:00:00Z")
    assert h1 == h2
    assert h1 != h3
    assert len(h1) == 64  # SHA-256 length


# ─── 5. Finding Lifecycle State Machine Tests ─────────────────────────────────

def test_finding_lifecycle_transitions():
    assert FindingStatus.VALIDATING in ALLOWED_TRANSITIONS[FindingStatus.NEW]
    assert FindingStatus.CONFIRMED in ALLOWED_TRANSITIONS[FindingStatus.VALIDATING]
    assert FindingStatus.REPORTED in ALLOWED_TRANSITIONS[FindingStatus.CONFIRMED]
    assert FindingStatus.RESOLVED in ALLOWED_TRANSITIONS[FindingStatus.RETEST]


# ─── 6. Compliance Mapping Tests ──────────────────────────────────────────────

def test_compliance_mapping():
    xss_map = ComplianceService.map_cwe_to_frameworks("CWE-79")
    assert "Injection" in xss_map["owasp"]
    assert "CIS 16.11" in xss_map["cis_controls"]

    bola_map = ComplianceService.map_cwe_to_frameworks("CWE-285")
    assert "API1:2023" in bola_map["owasp"]
    assert "ISO" in xss_map.get("iso_27001", "") or "A." in xss_map.get("iso_27001", "")


# ─── 7. Business Risk Scoring Tests ───────────────────────────────────────────

def test_business_risk_score():
    # Critical unauthenticated internet-facing finding on Critical asset
    score_crit = calculate_finding_business_risk(
        severity=Severity.CRITICAL,
        cvss_score=9.8,
        confidence=90,
        asset_criticality=BusinessCriticality.CRITICAL,
        is_internet_facing=True,
        auth_required=False,
        exploitability="HIGH",
    )
    assert score_crit >= 75.0

    # Low internal finding
    score_low = calculate_finding_business_risk(
        severity=Severity.LOW,
        cvss_score=2.5,
        confidence=60,
        asset_criticality=BusinessCriticality.LOW,
        is_internet_facing=False,
        auth_required=True,
        exploitability="LOW",
    )
    assert score_low <= 25.0
