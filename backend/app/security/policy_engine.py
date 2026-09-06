"""
Policy Engine — Deterministic Security & Authorization Validator

The AI reasoning engine NEVER makes direct HTTP requests or executes actions against targets.
Every single agent action must pass through the Policy Engine and Scope Validator before execution.
"""
from dataclasses import dataclass, field
from datetime import datetime, time, timezone
from enum import Enum
from typing import Optional, Any
import fnmatch
import time as time_module
import structlog

from app.core.scope_validator import ScopeValidator, ScopeViolationError

logger = structlog.get_logger(__name__)


class PolicyDecision(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    APPROVAL_REQUIRED = "APPROVAL_REQUIRED"


class PolicyViolationError(Exception):
    """Raised when an action violates safety or scope policies."""
    def __init__(self, message: str, rule: str = "POLICY_VIOLATION", decision: PolicyDecision = PolicyDecision.DENY):
        super().__init__(message)
        self.message = message
        self.rule = rule
        self.decision = decision


@dataclass
class PolicyResult:
    allowed: bool
    decision: PolicyDecision
    reason: str
    policy_rule: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: dict = field(default_factory=dict)


@dataclass
class PolicyConfig:
    environment: str = "development"  # production, staging, development, lab
    allowed_methods: list[str] = field(default_factory=lambda: ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
    allowed_ports: list[int] = field(default_factory=lambda: [80, 443, 8000, 8080, 8443, 3000, 5000])
    allowed_paths: list[str] = field(default_factory=lambda: ["*"])
    forbidden_paths: list[str] = field(default_factory=lambda: [
        "/admin/delete/*",
        "/api/internal/flush*",
        "/system/reboot*",
        "/system/shutdown*",
    ])
    max_requests_per_minute: int = 30
    max_concurrency: int = 5
    execution_window_start: Optional[str] = None  # e.g., "08:00"
    execution_window_end: Optional[str] = None    # e.g., "20:00"
    allowed_test_types: list[str] = field(default_factory=lambda: ["*"])
    forbidden_test_types: list[str] = field(default_factory=lambda: [
        "DESTRUCTIVE_DOS",
        "RANSOMWARE_SIMULATION",
        "DATA_DESTRUCTION",
    ])
    require_human_approval_for_destructive: bool = True
    high_risk_methods: list[str] = field(default_factory=lambda: ["DELETE"])


class RateLimiter:
    """In-memory sliding window rate limiter per target/project."""
    def __init__(self):
        self._timestamps: dict[str, list[float]] = {}

    def check_and_record(self, key: str, max_rpm: int) -> bool:
        now = time_module.time()
        window_start = now - 60.0

        if key not in self._timestamps:
            self._timestamps[key] = []

        # Prune old timestamps
        self._timestamps[key] = [t for t in self._timestamps[key] if t > window_start]

        if len(self._timestamps[key]) >= max_rpm:
            return False

        self._timestamps[key].append(now)
        return True

    def get_current_rpm(self, key: str) -> int:
        now = time_module.time()
        window_start = now - 60.0
        if key not in self._timestamps:
            return 0
        self._timestamps[key] = [t for t in self._timestamps[key] if t > window_start]
        return len(self._timestamps[key])


# Global in-memory rate limiter instance for worker processes
_global_rate_limiter = RateLimiter()


class PolicyEngine:
    """
    Deterministic Policy Engine validating every proposed test and request.
    """
    def __init__(
        self,
        scope_validator: Optional[ScopeValidator] = None,
        config: Optional[PolicyConfig] = None,
        rate_limiter: Optional[RateLimiter] = None,
    ):
        self.scope_validator = scope_validator or ScopeValidator()
        self.config = config or PolicyConfig()
        self.rate_limiter = rate_limiter or _global_rate_limiter

    def evaluate_request(
        self,
        target_url: str,
        method: str = "GET",
        test_type: str = "INSPECTION",
        agent_type: str = "GENERIC_AGENT",
        project_id: Optional[str] = None,
        is_simulated_only: bool = False,
    ) -> PolicyResult:
        """
        Validate all rules before an HTTP request is made.
        """
        method_upper = method.upper()

        # 1. Validate Scope Boundaries
        try:
            self.scope_validator.validate(target_url)
        except ScopeViolationError as e:
            logger.warning("🚫 Policy Denied: Scope Violation", target=target_url, error=str(e))
            return PolicyResult(
                allowed=False,
                decision=PolicyDecision.DENY,
                reason=f"Target is outside authorized scope: {str(e)}",
                policy_rule="SCOPE_VALIDATION_FAILED",
                metadata={"target": target_url},
            )

        # 2. Validate HTTP Method
        if self.config.allowed_methods and method_upper not in self.config.allowed_methods:
            return PolicyResult(
                allowed=False,
                decision=PolicyDecision.DENY,
                reason=f"HTTP Method {method_upper} is not allowed by policy. Allowed: {self.config.allowed_methods}",
                policy_rule="METHOD_NOT_ALLOWED",
                metadata={"method": method_upper},
            )

        # 3. Parse path from URL
        from urllib.parse import urlparse
        parsed = urlparse(target_url)
        path = parsed.path or "/"
        port = parsed.port or (443 if parsed.scheme == "https" else 80)

        # 4. Validate Port
        if self.config.allowed_ports and port not in self.config.allowed_ports:
            return PolicyResult(
                allowed=False,
                decision=PolicyDecision.DENY,
                reason=f"Port {port} is not in allowed ports list: {self.config.allowed_ports}",
                policy_rule="PORT_FORBIDDEN",
                metadata={"port": port},
            )

        # 5. Check Forbidden Paths
        for forbidden in self.config.forbidden_paths:
            if fnmatch.fnmatch(path, forbidden) or path.startswith(forbidden.rstrip("*")):
                return PolicyResult(
                    allowed=False,
                    decision=PolicyDecision.DENY,
                    reason=f"Path '{path}' matches forbidden policy pattern: '{forbidden}'",
                    policy_rule="PATH_FORBIDDEN",
                    metadata={"path": path, "forbidden_pattern": forbidden},
                )

        # 6. Check Allowed Paths if specified (and not wildcard)
        if self.config.allowed_paths and "*" not in self.config.allowed_paths:
            matched = any(fnmatch.fnmatch(path, pattern) for pattern in self.config.allowed_paths)
            if not matched:
                return PolicyResult(
                    allowed=False,
                    decision=PolicyDecision.DENY,
                    reason=f"Path '{path}' is not within allowed paths: {self.config.allowed_paths}",
                    policy_rule="PATH_NOT_IN_ALLOWLIST",
                    metadata={"path": path},
                )

        # 7. Check Test Type
        if test_type in self.config.forbidden_test_types:
            return PolicyResult(
                allowed=False,
                decision=PolicyDecision.DENY,
                reason=f"Test type '{test_type}' is strictly forbidden by policy.",
                policy_rule="TEST_TYPE_FORBIDDEN",
                metadata={"test_type": test_type},
            )

        # 8. Check Execution Window
        if not self._is_within_execution_window():
            return PolicyResult(
                allowed=False,
                decision=PolicyDecision.DENY,
                reason=f"Current time is outside the permitted execution window ({self.config.execution_window_start} - {self.config.execution_window_end}).",
                policy_rule="OUTSIDE_EXECUTION_WINDOW",
                metadata={
                    "start": self.config.execution_window_start,
                    "end": self.config.execution_window_end,
                },
            )

        # 9. Production Safety Rules & Human Approval Requirements
        if self.config.environment == "production":
            # Production cannot execute DELETE or destructive test types without explicit approval
            if method_upper in self.config.high_risk_methods or test_type in ["EXPLOITATION", "DESTRUCTIVE"]:
                if self.config.require_human_approval_for_destructive:
                    return PolicyResult(
                        allowed=False,
                        decision=PolicyDecision.APPROVAL_REQUIRED,
                        reason=f"Production safety rule: Action '{method_upper} {path}' ({test_type}) requires human approval before execution.",
                        policy_rule="PRODUCTION_APPROVAL_REQUIRED",
                        metadata={"environment": "production", "action": f"{method_upper} {path}"},
                    )

        # 10. Rate Limiting Check
        rate_key = project_id or parsed.netloc or "global"
        if not is_simulated_only:
            if not self.rate_limiter.check_and_record(rate_key, self.config.max_requests_per_minute):
                return PolicyResult(
                    allowed=False,
                    decision=PolicyDecision.DENY,
                    reason=f"Rate limit exceeded for {rate_key} (Max RPM: {self.config.max_requests_per_minute}).",
                    policy_rule="RATE_LIMIT_EXCEEDED",
                    metadata={"rpm_limit": self.config.max_requests_per_minute},
                )

        # Action is allowed
        return PolicyResult(
            allowed=True,
            decision=PolicyDecision.ALLOW,
            reason="Action passed all policy and scope validations.",
            policy_rule="ALLOW_DEFAULT",
            metadata={"target": target_url, "method": method_upper, "agent": agent_type},
        )

    def _is_within_execution_window(self) -> bool:
        """Check if local time falls inside execution window if configured."""
        if not self.config.execution_window_start or not self.config.execution_window_end:
            return True

        try:
            start_parts = [int(p) for p in self.config.execution_window_start.split(":")]
            end_parts = [int(p) for p in self.config.execution_window_end.split(":")]
            start_time = time(start_parts[0], start_parts[1])
            end_time = time(end_parts[0], end_parts[1])

            current_time = datetime.now(timezone.utc).time()

            if start_time <= end_time:
                return start_time <= current_time <= end_time
            else:
                # Over midnight window
                return current_time >= start_time or current_time <= end_time
        except Exception as e:
            logger.warning("Error parsing execution window, allowing by default", error=str(e))
            return True
