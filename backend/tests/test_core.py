"""
Backend unit tests
"""
import pytest
from app.core.scope_validator import ScopeValidator, ScopeViolationError
from app.services.risk_engine import calculate_finding_risk_score
from app.models import Severity, BusinessCriticality


# ─── Scope Validator Tests ────────────────────────────────────────────────────

class TestScopeValidator:

    def test_valid_domain_allowed(self):
        v = ScopeValidator(allowed_domains=["example.com"])
        v.validate("https://example.com/path")  # Should not raise

    def test_subdomain_allowed(self):
        v = ScopeValidator(allowed_domains=["example.com"])
        v.validate("https://app.example.com")  # Should not raise

    def test_out_of_scope_domain_raises(self):
        v = ScopeValidator(allowed_domains=["example.com"])
        with pytest.raises(ScopeViolationError):
            v.validate("https://evil.com")

    def test_excluded_domain_raises(self):
        v = ScopeValidator(allowed_domains=["example.com"], excluded_domains=["admin.example.com"])
        with pytest.raises(ScopeViolationError):
            v.validate("https://admin.example.com")

    def test_private_ip_blocked_by_default(self):
        v = ScopeValidator(allowed_ips=["192.168.1.100"])
        with pytest.raises(ScopeViolationError):
            v.validate("http://192.168.1.100")

    def test_private_ip_allowed_when_enabled(self):
        v = ScopeValidator(allowed_ips=["192.168.1.100"], allow_private_ips=True)
        v.validate("http://192.168.1.100")  # Should not raise

    def test_ip_not_in_allowlist_raises(self):
        v = ScopeValidator(allowed_ips=["1.2.3.4"], allow_private_ips=True)
        with pytest.raises(ScopeViolationError):
            v.validate("http://5.6.7.8")

    def test_cidr_range_allowed(self):
        v = ScopeValidator(allowed_cidrs=["10.0.0.0/8"], allow_private_ips=True)
        v.validate("http://10.1.2.3")  # Should not raise

    def test_excluded_path_raises(self):
        v = ScopeValidator(allowed_domains=["example.com"], excluded_paths=["/admin"])
        with pytest.raises(ScopeViolationError):
            v.validate("https://example.com/admin/dashboard")


# ─── Risk Engine Tests ────────────────────────────────────────────────────────

class TestRiskEngine:

    def test_critical_high_score(self):
        score = calculate_finding_risk_score(
            severity=Severity.CRITICAL,
            confidence=100,
            asset_criticality=BusinessCriticality.CRITICAL,
            is_internet_facing=True,
        )
        assert score >= 70, f"Critical finding should have high score, got {score}"

    def test_info_low_score(self):
        score = calculate_finding_risk_score(
            severity=Severity.INFO,
            confidence=50,
            asset_criticality=BusinessCriticality.LOW,
            is_internet_facing=False,
        )
        assert score < 20, f"Info finding should have low score, got {score}"

    def test_score_range(self):
        for sev in Severity:
            score = calculate_finding_risk_score(severity=sev, confidence=80)
            assert 0 <= score <= 100, f"Score out of range for {sev}: {score}"

    def test_internet_facing_increases_score(self):
        score_internal = calculate_finding_risk_score(Severity.HIGH, 80, is_internet_facing=False)
        score_external = calculate_finding_risk_score(Severity.HIGH, 80, is_internet_facing=True)
        assert score_external > score_internal

    def test_confidence_affects_score(self):
        score_low = calculate_finding_risk_score(Severity.HIGH, confidence=20)
        score_high = calculate_finding_risk_score(Severity.HIGH, confidence=100)
        assert score_high > score_low
