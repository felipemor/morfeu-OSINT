"""
Scope Validator — enforces that all agent requests stay within authorized boundaries.

CRITICAL SAFETY COMPONENT: every agent must call validate() before making any HTTP request.
"""
import ipaddress
import re
from urllib.parse import urlparse
from typing import Optional
import structlog

logger = structlog.get_logger(__name__)

PRIVATE_IP_RANGES = [
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
    ipaddress.IPv4Network("127.0.0.0/8"),
    ipaddress.IPv4Network("169.254.0.0/16"),
    ipaddress.IPv4Network("0.0.0.0/8"),
]

SENSITIVE_DATA_PATTERNS = [
    (r"(?i)(password|passwd|pwd)\s*[:=]\s*\S+", "PASSWORD"),
    (r"(?i)(api[_-]?key|apikey)\s*[:=]\s*\S+", "API_KEY"),
    (r"(?i)(secret|token)\s*[:=]\s*\S+", "SECRET"),
    (r"(?i)(Bearer\s+)[A-Za-z0-9\-._~+/]+=*", "BEARER_TOKEN"),
    (r"(?i)(Authorization:\s*)[^\r\n]+", "AUTH_HEADER"),
    (r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b", "CARD_NUMBER"),
    (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b", "EMAIL"),
]


class ScopeViolationError(Exception):
    """Raised when a target is outside the authorized scope."""
    pass


def mask_sensitive_data(text: str) -> str:
    """Mask credentials and PII in evidence before storage."""
    if not text:
        return text
    result = text
    for pattern, label in SENSITIVE_DATA_PATTERNS:
        result = re.sub(pattern, f"[MASKED:{label}]", result)
    return result


class ScopeValidator:
    """Validates that targets are within authorized scope before any request."""

    def __init__(
        self,
        allowed_domains: list[str] = None,
        allowed_ips: list[str] = None,
        allowed_cidrs: list[str] = None,
        excluded_domains: list[str] = None,
        excluded_ips: list[str] = None,
        excluded_paths: list[str] = None,
        allow_private_ips: bool = False,
    ):
        self.allowed_domains = [d.lower().lstrip("*.") for d in (allowed_domains or [])]
        self.allowed_ips = set(allowed_ips or [])
        self.allowed_cidrs = [ipaddress.IPv4Network(c, strict=False) for c in (allowed_cidrs or []) if c]
        self.excluded_domains = [d.lower() for d in (excluded_domains or [])]
        self.excluded_ips = set(excluded_ips or [])
        self.excluded_paths = excluded_paths or []
        self.allow_private_ips = allow_private_ips

    def validate(self, target: str, resolve_dns: bool = False) -> None:
        """
        Validate that target is within scope.
        Raises ScopeViolationError if out of scope.
        """
        # Parse URL or raw host
        if target.startswith("http://") or target.startswith("https://"):
            parsed = urlparse(target)
            host = parsed.hostname or ""
            path = parsed.path or "/"
        else:
            host = target.split(":")[0]
            path = "/"

        host = host.lower().strip()

        if not host:
            raise ScopeViolationError(f"Cannot parse host from: {target}")

        # Check excluded paths
        for ex_path in self.excluded_paths:
            if path.startswith(ex_path):
                raise ScopeViolationError(f"Path {path} is excluded from scope")

        # Determine if host is IP or domain
        try:
            ip = ipaddress.IPv4Address(host)
            self._validate_ip(str(ip))
        except ValueError:
            self._validate_domain(host)

    def _validate_ip(self, ip_str: str) -> None:
        ip = ipaddress.IPv4Address(ip_str)

        if ip_str in self.excluded_ips:
            raise ScopeViolationError(f"IP {ip_str} is explicitly excluded")

        # Block private IPs unless explicitly allowed
        if not self.allow_private_ips:
            for private_range in PRIVATE_IP_RANGES:
                if ip in private_range:
                    raise ScopeViolationError(
                        f"IP {ip_str} is in private range {private_range}. "
                        f"Set allow_private_ips=true to test internal targets."
                    )

        # Check allowlist
        if ip_str in self.allowed_ips:
            return

        for cidr in self.allowed_cidrs:
            if ip in cidr:
                return

        if self.allowed_ips or self.allowed_cidrs:
            raise ScopeViolationError(
                f"IP {ip_str} is not in the authorized scope. "
                f"Allowed IPs: {self.allowed_ips}, CIDRs: {self.allowed_cidrs}"
            )

    def _validate_domain(self, domain: str) -> None:
        if domain in self.excluded_domains:
            raise ScopeViolationError(f"Domain {domain} is explicitly excluded")

        for ex in self.excluded_domains:
            if domain.endswith("." + ex):
                raise ScopeViolationError(f"Domain {domain} is under excluded domain {ex}")

        if not self.allowed_domains:
            return  # No domain allowlist = allow all (IP-only scope)

        for allowed in self.allowed_domains:
            if domain == allowed or domain.endswith("." + allowed):
                return

        raise ScopeViolationError(
            f"Domain '{domain}' is not in authorized scope. "
            f"Allowed: {self.allowed_domains}"
        )
