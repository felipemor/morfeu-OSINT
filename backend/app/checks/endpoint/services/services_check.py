"""
Endpoint Listening Services & Insecure Service Paths Check
"""
from app.checks.endpoint.base import BaseEndpointCheck, EndpointCheckContext, EndpointCheckResult
from app.models import Severity


class ServiceAssessmentCheck(BaseEndpointCheck):
    id = "EP-SVC-001"
    name = "Insecure Services & Listening Ports Check"
    category = "SERVICES"
    severity = Severity.MEDIUM
    cwe_id = "CWE-428"
    owasp_category = "A05:2021-Security Misconfiguration"

    INSECURE_PORTS = {
        21: "FTP (Plaintext)",
        23: "Telnet (Unencrypted remote access)",
        69: "TFTP (Unauthenticated file transfer)",
        512: "Rexec (Legacy plaintext protocol)",
        513: "Rlogin (Legacy plaintext protocol)",
    }

    async def evaluate(self, context: EndpointCheckContext) -> EndpointCheckResult:
        services_data = context.telemetry_data.get("services", [])
        listening_ports = context.telemetry_data.get("listening_ports", [])

        detected_insecure = []
        for port_info in listening_ports:
            port = port_info if isinstance(port_info, int) else port_info.get("port")
            if port in self.INSECURE_PORTS:
                detected_insecure.append(f"Port {port} ({self.INSECURE_PORTS[port]})")

        if detected_insecure:
            return EndpointCheckResult(
                check_id=self.id,
                agent_id=context.agent_id,
                asset_id=context.asset_id,
                status="FAIL",
                title=f"Legacy / Insecure Plaintext Services Detected on {context.hostname}",
                description=f"Host is listening on insecure legacy ports: {', '.join(detected_insecure)}.",
                severity=Severity.HIGH,
                cwe_id="CWE-319",
                owasp_category=self.owasp_category,
                remediation="Disable legacy plaintext protocols and migrate to SSH/TLS.",
                evidence={"insecure_ports": detected_insecure, "all_listening": listening_ports},
            )

        return EndpointCheckResult(
            check_id=self.id,
            agent_id=context.agent_id,
            asset_id=context.asset_id,
            status="PASS",
            title=f"No Insecure Legacy Ports Exposed on {context.hostname}",
            description="All active services adhere to standard secure protocols.",
            severity=Severity.INFO,
            cwe_id=self.cwe_id,
            owasp_category=self.owasp_category,
            remediation="No action required.",
            evidence={"listening_ports_count": len(listening_ports)},
        )
