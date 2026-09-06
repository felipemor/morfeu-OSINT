from typing import Dict, Type, List, Optional
from app.checks.endpoint.base import BaseEndpointCheck
from app.checks.endpoint.firewall.firewall_check import FirewallAssessmentCheck
from app.checks.endpoint.services.services_check import ServiceAssessmentCheck
from app.checks.endpoint.security_controls.controls_check import SecurityControlsCheck
from app.checks.endpoint.os.os_check import OsAssessmentCheck
from app.checks.endpoint.patch.patch_check import PatchAssessmentCheck

class EndpointCheckRegistry:
    """
    Registry for all endpoint assessment checks.
    """
    def __init__(self):
        self._checks: Dict[str, BaseEndpointCheck] = {}
        self._register_defaults()

    def _register_defaults(self):
        default_checks = [
            FirewallAssessmentCheck(),
            ServiceAssessmentCheck(),
            SecurityControlsCheck(),
            OsAssessmentCheck(),
            PatchAssessmentCheck(),
        ]
        for check in default_checks:
            self.register(check)

    def register(self, check: BaseEndpointCheck) -> None:
        cid = getattr(check, "check_id", getattr(check, "id", None))
        if cid:
            self._checks[cid] = check

    def get_check(self, check_id: str) -> Optional[BaseEndpointCheck]:
        return self._checks.get(check_id)

    def list_checks(self) -> List[BaseEndpointCheck]:
        return list(self._checks.values())

    def get_checks_for_platform(self, platform_name: str) -> List[BaseEndpointCheck]:
        platform_lower = platform_name.lower()
        res = []
        for check in self._checks.values():
            if check.supported_platforms == ["*"] or any(p in platform_lower for p in check.supported_platforms):
                res.append(check)
        return res

endpoint_check_registry = EndpointCheckRegistry()
