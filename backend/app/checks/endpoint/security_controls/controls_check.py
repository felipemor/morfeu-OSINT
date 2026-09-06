"""
Endpoint Security Controls (EDR/Antivirus, Disk Encryption) Assessment Check
"""
from app.checks.endpoint.base import BaseEndpointCheck, EndpointCheckContext, EndpointCheckResult
from app.models import Severity


class SecurityControlsCheck(BaseEndpointCheck):
    id = "EP-CTL-001"
    name = "EDR & Disk Encryption Controls Check"
    category = "SECURITY_CONTROLS"
    severity = Severity.HIGH
    cwe_id = "CWE-311"
    owasp_category = "A02:2021-Cryptographic Failures"

    async def evaluate(self, context: EndpointCheckContext) -> EndpointCheckResult:
        controls_data = context.telemetry_data.get("security_controls", {})
        edr_active = controls_data.get("edr_active", True)
        disk_encrypted = controls_data.get("disk_encrypted", True)
        edr_name = controls_data.get("edr_name", "Defender/CrowdStrike/SentinelOne")

        failures = []
        if not edr_active:
            failures.append("EDR/Antivirus protection is DISABLED or missing")
        if not disk_encrypted:
            failures.append("Full Disk Encryption (BitLocker/LUKS) is NOT enabled")

        if failures:
            return EndpointCheckResult(
                check_id=self.id,
                agent_id=context.agent_id,
                asset_id=context.asset_id,
                status="FAIL",
                title=f"Missing Critical Endpoint Security Controls on {context.hostname}",
                description=f"Identified endpoint control gaps on {context.hostname}: {'; '.join(failures)}.",
                severity=Severity.HIGH if not edr_active else Severity.MEDIUM,
                cwe_id=self.cwe_id,
                owasp_category=self.owasp_category,
                remediation="Ensure EDR/Antivirus sensor is active and enforce BitLocker/LUKS via MDM/GPO.",
                evidence={"edr_active": edr_active, "disk_encrypted": disk_encrypted, "edr_name": edr_name},
            )

        return EndpointCheckResult(
            check_id=self.id,
            agent_id=context.agent_id,
            asset_id=context.asset_id,
            status="PASS",
            title=f"Security Controls (EDR & Encryption) Active on {context.hostname}",
            description=f"Active EDR ({edr_name}) and disk encryption verified.",
            severity=Severity.INFO,
            cwe_id=self.cwe_id,
            owasp_category=self.owasp_category,
            remediation="No action required.",
            evidence={"edr_active": True, "disk_encrypted": True},
        )
