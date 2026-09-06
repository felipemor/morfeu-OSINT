"""
Tests for OSINT Reconnaissance Service & Router
"""
import asyncio
from app.services.osint_service import osint_service


def test_osint_service_dns_intelligence():
    async def run():
        dns_res = await osint_service.get_dns_intelligence("stellantis.com")
        assert "domain" in dns_res
        assert "records" in dns_res
        assert "A" in dns_res["records"]
        assert dns_res["domain"] == "stellantis.com"

    asyncio.run(run())


def test_osint_service_certificate_transparency():
    async def run():
        cert_res = await osint_service.get_certificate_transparency("stellantis.com")
        assert "discovered_subdomains" in cert_res
        assert "active_cert" in cert_res
        assert cert_res["discovered_subdomains_count"] >= 1

    asyncio.run(run())


def test_osint_full_reconnaissance_pipeline():
    async def run():
        full_res = await osint_service.run_full_osint_investigation("stellantis.com")
        assert full_res["target"] == "stellantis.com"
        assert "threat_exposure_score" in full_res
        assert "threat_level" in full_res
        assert "dns_intelligence" in full_res
        assert "certificate_intelligence" in full_res
        assert "infrastructure_asn" in full_res
        assert "technology_fingerprint" in full_res
        assert "email_security" in full_res
        assert "public_exposure" in full_res

    asyncio.run(run())
