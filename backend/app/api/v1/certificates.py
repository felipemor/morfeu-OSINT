"""
Certificate & PKI Generator API — AegisLattice Crypto Engine.
Provides endpoints for creating asymmetric keys, CSRs, SANs, Subject Attributes,
X.509 certificates (mTLS, Client Auth, Web, Code Signing), Let's Encrypt modes,
and downloading PKI artifact bundles (.zip, .csr, .crt, .pem, .key).
"""

from fastapi import APIRouter, HTTPException, Response, status
from pydantic import BaseModel, Field
from typing import Any, Dict, List, Optional

from app.services import cert_generator_service as svc
from app.services.cert_generator_service import (
    CertProfile,
    IssuanceMode,
    KeyAlgorithm,
    SANType,
)

router = APIRouter()


class CustomAttributeItem(BaseModel):
    oid_or_name: str
    value: str


class SANItem(BaseModel):
    type: str = Field(default="DNS", description="DNS | IP | URI | EMAIL | RID | DIRNAME | OTHERNAME")
    value: str
    oid: Optional[str] = Field(default=None, description="Only for OTHERNAME")


class CustomUsages(BaseModel):
    digital_signature: bool = True
    key_encipherment: bool = True
    key_agreement: bool = False
    content_commitment: bool = False
    server_auth: bool = False
    client_auth: bool = False
    code_signing: bool = False
    email_protection: bool = False


class CertificateGenerateRequest(BaseModel):
    common_names: List[str] = Field(default=["example.com"], description="List of common names")
    country: Optional[str] = Field(default="BR", description="2-letter ISO Country Code")
    state: Optional[str] = Field(default="SP", description="State or Province")
    locality: Optional[str] = Field(default="Sao Paulo", description="City / Locality")
    organization: Optional[str] = Field(default="Morfeu Security Lab", description="Organization name")
    organizational_unit: Optional[str] = Field(default="Cryptography Division", description="Department / OU")
    email: Optional[str] = Field(default="security@morfeu.local", description="Contact email")
    custom_attributes: Optional[List[CustomAttributeItem]] = Field(default=[], description="Extra Subject attributes")
    san_list: Optional[List[SANItem]] = Field(default=[], description="Subject Alternative Names")
    key_algorithm: KeyAlgorithm = Field(default=KeyAlgorithm.RSA_2048, description="Asymmetric key algorithm")
    cert_profile: CertProfile = Field(default=CertProfile.MUTUAL_TLS, description="Certificate usage profile")
    issuance_mode: IssuanceMode = Field(default=IssuanceMode.PRIVATE_LETS_ENCRYPT, description="Issuance type")
    validity_days: int = Field(default=90, ge=1, le=3650, description="Validity period in days")
    key_password: Optional[str] = Field(default=None, description="Optional PEM encryption password")
    custom_usages: Optional[CustomUsages] = Field(default=None, description="Only used if profile is CUSTOM")


class ParseCSRRequest(BaseModel):
    csr_pem: str


class SignCSRRequest(BaseModel):
    csr_pem: str
    cert_profile: CertProfile = Field(default=CertProfile.MUTUAL_TLS)
    issuance_mode: IssuanceMode = Field(default=IssuanceMode.PRIVATE_LETS_ENCRYPT)
    validity_days: int = Field(default=90, ge=1, le=3650)
    custom_usages: Optional[CustomUsages] = None


class ParseCertRequest(BaseModel):
    cert_pem: str


class DownloadBundleRequest(BaseModel):
    filename_base: str = "certificate"
    key_pem: str
    csr_pem: str
    crt_pem: str
    pem_fullchain: str
    readme_content: Optional[str] = None


@router.post("/generate", status_code=status.HTTP_200_OK)
async def generate_certificate(body: CertificateGenerateRequest):
    """
    Generate Private Key, CSR, X.509 Certificate and Fullchain PEM with all requested
    Subject Attributes, SANs, and Profile configurations.
    """
    try:
        custom_attrs = [a.model_dump() for a in (body.custom_attributes or [])]
        sans = [s.model_dump() for s in (body.san_list or [])]
        custom_u = body.custom_usages.model_dump() if body.custom_usages else None

        result = svc.generate_pki_artifacts(
            common_names=body.common_names,
            country=body.country,
            state=body.state,
            locality=body.locality,
            organization=body.organization,
            organizational_unit=body.organizational_unit,
            email=body.email,
            custom_attributes=custom_attrs,
            san_list=sans,
            key_algorithm=body.key_algorithm,
            cert_profile=body.cert_profile,
            issuance_mode=body.issuance_mode,
            validity_days=body.validity_days,
            key_password=body.key_password,
            custom_usages=custom_u,
        )
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Erro na geração dos artefatos criptográficos: {str(e)}")


@router.post("/sign-csr", status_code=status.HTTP_200_OK)
async def sign_csr(body: SignCSRRequest):
    """
    Sign an existing/pasted CSR using the selected CA / Let's Encrypt authority profile.
    """
    try:
        custom_u = body.custom_usages.model_dump() if body.custom_usages else None
        result = svc.sign_pasted_csr(
            csr_pem=body.csr_pem,
            cert_profile=body.cert_profile,
            issuance_mode=body.issuance_mode,
            validity_days=body.validity_days,
            custom_usages=custom_u,
        )
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Erro ao assinar CSR: {str(e)}")


@router.post("/parse-csr", status_code=status.HTTP_200_OK)
async def parse_csr(body: ParseCSRRequest):
    """Inspect and decode an existing PEM-encoded CSR."""
    res = svc.parse_csr_text(body.csr_pem)
    if not res.get("valid"):
        raise HTTPException(status_code=400, detail=res.get("error", "CSR inválido"))
    return res


@router.post("/parse-cert", status_code=status.HTTP_200_OK)
async def parse_cert(body: ParseCertRequest):
    """Inspect and decode an existing PEM-encoded X.509 Certificate."""
    res = svc.parse_cert_text(body.cert_pem)
    if not res.get("valid"):
        raise HTTPException(status_code=400, detail=res.get("error", "Certificado inválido"))
    return res


@router.post("/download-bundle", status_code=status.HTTP_200_OK)
async def download_bundle(body: DownloadBundleRequest):
    """Package and download all 4 files (.key, .csr, .crt, .pem) in a single ZIP archive."""
    try:
        zip_bytes = svc.create_bundle_zip(
            filename_base=body.filename_base or "certificate",
            key_pem=body.key_pem,
            csr_pem=body.csr_pem,
            crt_pem=body.crt_pem,
            pem_fullchain=body.pem_fullchain,
            readme_content=body.readme_content,
        )
        filename = f"{body.filename_base or 'certificate'}_bundle.zip"
        return Response(
            content=zip_bytes,
            media_type="application/zip",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Erro ao empacotar arquivo ZIP: {str(e)}")
