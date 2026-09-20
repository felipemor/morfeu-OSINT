"""
Unit and integration tests for PKI Certificate Generator service and endpoints.
"""

import pytest
from app.services import cert_generator_service as svc
from app.services.cert_generator_service import (
    CertProfile,
    IssuanceMode,
    KeyAlgorithm,
)


def test_rsa_mutual_tls_generation():
    """Test generating an RSA Mutual TLS certificate with full Subject and SANs."""
    sans = [
        {"type": "DNS", "value": "api.example.com"},
        {"type": "DNS", "value": "*.example.com"},
        {"type": "IP", "value": "192.168.1.100"},
        {"type": "URI", "value": "spiffe://cluster.local/ns/prod/sa/app"},
        {"type": "EMAIL", "value": "admin@example.com"},
        {"type": "RID", "value": "1.3.6.1.4.1.99999"},
        {"type": "OTHERNAME", "value": "user@REALM.COM", "oid": "1.3.6.1.4.1.311.20.2.3"},
    ]
    custom_attrs = [
        {"oid_or_name": "TITLE", "value": "Security Lead"},
        {"oid_or_name": "STREET", "value": "Av Paulista 1000"},
    ]

    res = svc.generate_pki_artifacts(
        common_names=["api.example.com", "vault.example.com"],
        country="BR",
        state="Sao Paulo",
        locality="Sao Paulo",
        organization="Fintech SA",
        organizational_unit="Security Core",
        email="pki@fintech.com.br",
        custom_attributes=custom_attrs,
        san_list=sans,
        key_algorithm=KeyAlgorithm.RSA_2048,
        cert_profile=CertProfile.MUTUAL_TLS,
        issuance_mode=IssuanceMode.PRIVATE_LETS_ENCRYPT,
        validity_days=90,
    )

    assert "files" in res
    assert "metadata" in res
    assert "-----BEGIN PRIVATE KEY-----" in res["files"]["key"]
    assert "-----BEGIN CERTIFICATE REQUEST-----" in res["files"]["csr"]
    assert "-----BEGIN CERTIFICATE-----" in res["files"]["crt"]
    assert "-----BEGIN CERTIFICATE-----" in res["files"]["pem"]

    meta = res["metadata"]
    assert meta["primary_common_name"] == "api.example.com"
    assert "CN=api.example.com" in meta["subject_dn"] or "CN=vault.example.com" in meta["subject_dn"]
    assert "O=Fintech SA" in meta["subject_dn"]
    assert meta["profile"] == "MUTUAL_TLS"
    assert meta["fingerprint_sha256"] is not None
    assert meta["san_count"] >= 7


def test_ecdsa_code_signing_generation():
    """Test generating ECDSA Code Signing certificate."""
    res = svc.generate_pki_artifacts(
        common_names=["Software Publisher 2026"],
        country="US",
        state="California",
        locality="San Francisco",
        organization="CodeSign LLC",
        san_list=[{"type": "DNS", "value": "codesign.internal"}],
        key_algorithm=KeyAlgorithm.ECDSA_P256,
        cert_profile=CertProfile.CODE_SIGNING,
        issuance_mode=IssuanceMode.SELF_SIGNED_CA,
        validity_days=365,
    )

    assert "-----BEGIN PRIVATE KEY-----" in res["files"]["key"]
    assert "-----BEGIN CERTIFICATE REQUEST-----" in res["files"]["csr"]
    assert "-----BEGIN CERTIFICATE-----" in res["files"]["crt"]
    assert res["metadata"]["profile"] == "CODE_SIGNING"
    assert res["metadata"]["key_algorithm"] == "ECDSA_P256"


def test_ed25519_client_auth_generation():
    """Test generating Ed25519 Client Authenticator certificate."""
    res = svc.generate_pki_artifacts(
        common_names=["client-workstation-01"],
        san_list=[
            {"type": "EMAIL", "value": "operator@morfeu.local"},
            {"type": "IP", "value": "10.10.0.50"},
        ],
        key_algorithm=KeyAlgorithm.ED25519,
        cert_profile=CertProfile.CLIENT_AUTH,
        issuance_mode=IssuanceMode.PRIVATE_LETS_ENCRYPT,
        validity_days=30,
    )

    assert "-----BEGIN PRIVATE KEY-----" in res["files"]["key"]
    assert "-----BEGIN CERTIFICATE REQUEST-----" in res["files"]["csr"]
    assert "-----BEGIN CERTIFICATE-----" in res["files"]["crt"]
    assert res["metadata"]["key_algorithm"] == "ED25519"


def test_parse_csr_and_cert():
    """Test parsing generated CSR and Certificate."""
    gen = svc.generate_pki_artifacts(
        common_names=["test.portal.com"],
        country="BR",
        organization="Morfeu Labs",
        san_list=[{"type": "DNS", "value": "test.portal.com"}, {"type": "IP", "value": "127.0.0.1"}],
        key_algorithm=KeyAlgorithm.RSA_2048,
    )

    csr_info = svc.parse_csr_text(gen["files"]["csr"])
    assert csr_info["valid"] is True
    assert csr_info["is_signature_valid"] is True
    assert any(s["value"] == "test.portal.com" for s in csr_info["sans"])

    cert_info = svc.parse_cert_text(gen["files"]["crt"])
    assert cert_info["valid"] is True
    assert cert_info["serial_hex"] is not None


def test_sign_pasted_csr():
    """Test signing a pasted CSR directly."""
    # 1. First generate a CSR
    gen = svc.generate_pki_artifacts(
        common_names=["app.pasted-csr.com"],
        country="BR",
        organization="Bank Security Corp",
        san_list=[{"type": "DNS", "value": "app.pasted-csr.com"}, {"type": "IP", "value": "10.0.0.1"}],
    )
    csr_text = gen["files"]["csr"]

    # 2. Sign the pasted CSR
    signed = svc.sign_pasted_csr(
        csr_pem=csr_text,
        cert_profile=CertProfile.MUTUAL_TLS,
        issuance_mode=IssuanceMode.PRIVATE_LETS_ENCRYPT,
        validity_days=60,
    )

    assert "files" in signed
    assert "-----BEGIN CERTIFICATE-----" in signed["files"]["crt"]
    assert "-----BEGIN CERTIFICATE-----" in signed["files"]["pem"]
    assert signed["metadata"]["primary_common_name"] == "app.pasted-csr.com"
    assert signed["metadata"]["validity_days"] == 60


def test_bundle_zip_creation():

    """Test packaging zip archive."""
    gen = svc.generate_pki_artifacts(
        common_names=["test.zip.domain"],
        key_algorithm=KeyAlgorithm.RSA_2048,
    )

    zip_bytes = svc.create_bundle_zip(
        filename_base="test_domain",
        key_pem=gen["files"]["key"],
        csr_pem=gen["files"]["csr"],
        crt_pem=gen["files"]["crt"],
        pem_fullchain=gen["files"]["pem"],
    )

    assert len(zip_bytes) > 500
    assert zip_bytes[:4] == b"PK\x03\x04"
