"""
Certificate & PKI Generation Service — AegisLattice Crypto Engine.
Handles Key generation (RSA, ECDSA, Ed25519), PKCS#10 CSR construction,
Subject DN attributes, Subject Alternative Names (DNS, IP, URI, Email, RID, dirName, otherName),
Key Usages / Extended Key Usages (mTLS, Client Auth, Web Server, Code Signing),
and Let's Encrypt / Private CA full certificate (.crt, .pem, .csr, .key) generation.
"""

import io
import ipaddress
import zipfile
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID, ObjectIdentifier


class KeyAlgorithm(str, Enum):
    RSA_2048 = "RSA_2048"
    RSA_3072 = "RSA_3072"
    RSA_4096 = "RSA_4096"
    ECDSA_P256 = "ECDSA_P256"
    ECDSA_P384 = "ECDSA_P384"
    ECDSA_P521 = "ECDSA_P521"
    ED25519 = "ED25519"


class CertProfile(str, Enum):
    MUTUAL_TLS = "MUTUAL_TLS"          # Client + Server Auth (mTLS)
    CLIENT_AUTH = "CLIENT_AUTH"        # TLS Client Authentication
    WEB_SERVER = "WEB_SERVER"          # TLS Web Server Authentication (HTTPS)
    CODE_SIGNING = "CODE_SIGNING"      # Code Signing & Software Publisher
    EMAIL_PROTECTION = "EMAIL_PROTECTION"  # S/MIME Email Protection
    CUSTOM = "CUSTOM"                  # Custom Key Usages


class IssuanceMode(str, Enum):
    PUBLIC_LETS_ENCRYPT = "PUBLIC_LETS_ENCRYPT"  # ACME CSR for Let's Encrypt Public Authority
    PRIVATE_LETS_ENCRYPT = "PRIVATE_LETS_ENCRYPT"  # Private CA / Emulate Let's Encrypt hierarchy
    SELF_SIGNED_CA = "SELF_SIGNED_CA"              # Self-Signed Root Certificate


class SANType(str, Enum):
    DNS = "DNS"
    IP = "IP"
    URI = "URI"
    EMAIL = "EMAIL"
    RID = "RID"
    DIRNAME = "DIRNAME"
    OTHERNAME = "OTHERNAME"


def _generate_private_key(algo: KeyAlgorithm):
    """Generate asymmetric private key according to chosen algorithm."""
    if algo == KeyAlgorithm.RSA_2048:
        return rsa.generate_private_key(public_exponent=65537, key_size=2048)
    elif algo == KeyAlgorithm.RSA_3072:
        return rsa.generate_private_key(public_exponent=65537, key_size=3072)
    elif algo == KeyAlgorithm.RSA_4096:
        return rsa.generate_private_key(public_exponent=65537, key_size=4096)
    elif algo == KeyAlgorithm.ECDSA_P256:
        return ec.generate_private_key(ec.SECP256R1())
    elif algo == KeyAlgorithm.ECDSA_P384:
        return ec.generate_private_key(ec.SECP384R1())
    elif algo == KeyAlgorithm.ECDSA_P521:
        return ec.generate_private_key(ec.SECP521R1())
    elif algo == KeyAlgorithm.ED25519:
        return ed25519.Ed25519PrivateKey.generate()
    else:
        return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _build_subject_name(
    common_names: List[str],
    country: Optional[str] = None,
    state: Optional[str] = None,
    locality: Optional[str] = None,
    organization: Optional[str] = None,
    organizational_unit: Optional[str] = None,
    email: Optional[str] = None,
    custom_attributes: Optional[List[Dict[str, str]]] = None,
) -> x509.Name:
    """Build X.509 Subject Distinguished Name (DN)."""
    name_attributes = []

    if country and len(country.strip()) > 0:
        name_attributes.append(x509.NameAttribute(NameOID.COUNTRY_NAME, country.strip()[:2].upper()))
    if state and state.strip():
        name_attributes.append(x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state.strip()))
    if locality and locality.strip():
        name_attributes.append(x509.NameAttribute(NameOID.LOCALITY_NAME, locality.strip()))
    if organization and organization.strip():
        name_attributes.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization.strip()))
    if organizational_unit and organizational_unit.strip():
        name_attributes.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, organizational_unit.strip()))
    if email and email.strip():
        name_attributes.append(x509.NameAttribute(NameOID.EMAIL_ADDRESS, email.strip()))

    for cn in common_names:
        if cn and cn.strip():
            name_attributes.append(x509.NameAttribute(NameOID.COMMON_NAME, cn.strip()))

    # Process custom subject attributes if specified (e.g. OID:value or Name:value)
    if custom_attributes:
        for attr in custom_attributes:
            oid_or_name = attr.get("oid_or_name", "").strip()
            val = attr.get("value", "").strip()
            if not oid_or_name or not val:
                continue

            # Check known short names
            known = {
                "SERIALNUMBER": NameOID.SERIAL_NUMBER,
                "TITLE": NameOID.TITLE,
                "SURNAME": NameOID.SURNAME,
                "GIVENNAME": NameOID.GIVEN_NAME,
                "PSEUDONYM": NameOID.PSEUDONYM,
                "STREET": NameOID.STREET_ADDRESS,
                "POSTALCODE": NameOID.POSTAL_CODE,
            }
            oid_obj = known.get(oid_or_name.upper())
            if not oid_obj:
                try:
                    oid_obj = ObjectIdentifier(oid_or_name)
                except Exception:
                    oid_obj = NameOID.UNSTRUCTURED_NAME

            name_attributes.append(x509.NameAttribute(oid_obj, val))

    if not name_attributes:
        name_attributes.append(x509.NameAttribute(NameOID.COMMON_NAME, "localhost"))

    return x509.Name(name_attributes)


def _encode_der_utf8string(val: str) -> bytes:
    """Encode string as DER UTF8String (tag 0x0C)."""
    raw = val.encode("utf-8")
    length = len(raw)
    if length < 128:
        return bytes([0x0C, length]) + raw
    else:
        len_bytes = length.to_bytes((length.bit_length() + 7) // 8, "big")
        return bytes([0x0C, 0x80 | len(len_bytes)]) + len_bytes + raw


def _build_san_extension(san_list: List[Dict[str, str]]) -> Optional[x509.SubjectAlternativeName]:
    """Build SubjectAlternativeName extension from list of typed SAN items."""
    general_names: List[x509.GeneralName] = []

    for item in san_list:
        stype = item.get("type", "").upper().strip()
        val = item.get("value", "").strip()
        if not val:
            continue

        try:
            if stype == SANType.DNS.value:
                general_names.append(x509.DNSName(val))
            elif stype == SANType.IP.value:
                ip_obj = ipaddress.ip_address(val)
                general_names.append(x509.IPAddress(ip_obj))
            elif stype == SANType.URI.value:
                general_names.append(x509.UniformResourceIdentifier(val))
            elif stype == SANType.EMAIL.value:
                general_names.append(x509.RFC822Name(val))
            elif stype == SANType.RID.value:
                general_names.append(x509.RegisteredID(ObjectIdentifier(val)))
            elif stype == SANType.DIRNAME.value:
                dn_parts = [p.strip() for p in val.split(",") if "=" in p]
                attrs = []
                for p in dn_parts:
                    k, v = p.split("=", 1)
                    k_upper = k.strip().upper()
                    if k_upper == "CN":
                        attrs.append(x509.NameAttribute(NameOID.COMMON_NAME, v.strip()))
                    elif k_upper == "O":
                        attrs.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, v.strip()))
                    elif k_upper == "C":
                        attrs.append(x509.NameAttribute(NameOID.COUNTRY_NAME, v.strip()))
                    else:
                        attrs.append(x509.NameAttribute(NameOID.UNSTRUCTURED_NAME, v.strip()))
                if attrs:
                    general_names.append(x509.DirectoryName(x509.Name(attrs)))
            elif stype == SANType.OTHERNAME.value:
                oid_str = item.get("oid") or "1.3.6.1.4.1.311.20.2.3"  # Default: UPN
                # If val is hex DER or plain text, encode accordingly
                try:
                    if val.startswith("0x") or val.startswith("0X"):
                        der_bytes = bytes.fromhex(val[2:])
                    else:
                        der_bytes = _encode_der_utf8string(val)
                except Exception:
                    der_bytes = _encode_der_utf8string(val)
                general_names.append(x509.OtherName(ObjectIdentifier(oid_str), der_bytes))
        except Exception:
            # Fallback to DNS if parsing failed
            general_names.append(x509.DNSName(val))

    if general_names:
        return x509.SubjectAlternativeName(general_names)
    return None


def _get_key_usages_for_profile(profile: CertProfile, custom_usages: Optional[Dict[str, bool]] = None):
    """Determine KeyUsage and ExtendedKeyUsage based on profile."""
    eku_list = []
    digital_signature = True
    key_encipherment = True
    key_agreement = False
    content_commitment = False
    code_signing_usage = False

    if profile == CertProfile.MUTUAL_TLS:
        eku_list = [ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]
        digital_signature = True
        key_encipherment = True
        key_agreement = True
    elif profile == CertProfile.CLIENT_AUTH:
        eku_list = [ExtendedKeyUsageOID.CLIENT_AUTH]
        digital_signature = True
        key_encipherment = True
    elif profile == CertProfile.WEB_SERVER:
        eku_list = [ExtendedKeyUsageOID.SERVER_AUTH]
        digital_signature = True
        key_encipherment = True
        key_agreement = True
    elif profile == CertProfile.CODE_SIGNING:
        eku_list = [ExtendedKeyUsageOID.CODE_SIGNING]
        digital_signature = True
        key_encipherment = False
        code_signing_usage = True
        content_commitment = True
    elif profile == CertProfile.EMAIL_PROTECTION:
        eku_list = [ExtendedKeyUsageOID.EMAIL_PROTECTION]
        digital_signature = True
        key_encipherment = True
        content_commitment = True
    elif profile == CertProfile.CUSTOM and custom_usages:
        digital_signature = custom_usages.get("digital_signature", True)
        key_encipherment = custom_usages.get("key_encipherment", True)
        key_agreement = custom_usages.get("key_agreement", False)
        content_commitment = custom_usages.get("content_commitment", False)
        if custom_usages.get("server_auth", False):
            eku_list.append(ExtendedKeyUsageOID.SERVER_AUTH)
        if custom_usages.get("client_auth", False):
            eku_list.append(ExtendedKeyUsageOID.CLIENT_AUTH)
        if custom_usages.get("code_signing", False):
            eku_list.append(ExtendedKeyUsageOID.CODE_SIGNING)
        if custom_usages.get("email_protection", False):
            eku_list.append(ExtendedKeyUsageOID.EMAIL_PROTECTION)

    key_usage = x509.KeyUsage(
        digital_signature=digital_signature,
        content_commitment=content_commitment,
        key_encipherment=key_encipherment,
        data_encipherment=False,
        key_agreement=key_agreement,
        key_cert_sign=False,
        crl_sign=False,
        encipher_only=False,
        decipher_only=False,
    )

    extended_key_usage = x509.ExtendedKeyUsage(eku_list) if eku_list else None
    return key_usage, extended_key_usage


def generate_pki_artifacts(
    common_names: List[str],
    country: Optional[str] = "BR",
    state: Optional[str] = "SP",
    locality: Optional[str] = "Sao Paulo",
    organization: Optional[str] = "Morfeu Security Lab",
    organizational_unit: Optional[str] = "Cryptography Division",
    email: Optional[str] = "security@morfeu.local",
    custom_attributes: Optional[List[Dict[str, str]]] = None,
    san_list: Optional[List[Dict[str, str]]] = None,
    key_algorithm: KeyAlgorithm = KeyAlgorithm.RSA_2048,
    cert_profile: CertProfile = CertProfile.MUTUAL_TLS,
    issuance_mode: IssuanceMode = IssuanceMode.PRIVATE_LETS_ENCRYPT,
    validity_days: int = 90,
    key_password: Optional[str] = None,
    custom_usages: Optional[Dict[str, bool]] = None,
) -> Dict[str, Any]:
    """
    Core function to generate:
    1. Private Key (.key)
    2. PKCS#10 Certificate Signing Request (.csr)
    3. X.509 Certificate (.crt)
    4. PEM Bundle / Fullchain (.pem)
    5. Detailed inspection metadata (fingerprints, serial, ASN.1 parameters)
    """
    if not common_names or len(common_names) == 0:
        common_names = ["localhost"]

    san_list = san_list or []
    # If primary common name is not in SAN DNS, ensure it is added for modern browsers/TLS
    primary_cn = common_names[0]
    existing_dns = [s.get("value") for s in san_list if s.get("type", "").upper() == "DNS"]
    if primary_cn not in existing_dns and not primary_cn.startswith("*."):
        # Check if primary_cn is not an IP
        try:
            ipaddress.ip_address(primary_cn)
            san_list.insert(0, {"type": "IP", "value": primary_cn})
        except ValueError:
            san_list.insert(0, {"type": "DNS", "value": primary_cn})

    # 1. Generate Private Key
    private_key = _generate_private_key(key_algorithm)

    if key_password:
        encryption = serialization.BestAvailableEncryption(key_password.encode("utf-8"))
    else:
        encryption = serialization.NoEncryption()

    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption,
    ).decode("utf-8")

    # 2. Build Subject DN
    subject = _build_subject_name(
        common_names=common_names,
        country=country,
        state=state,
        locality=locality,
        organization=organization,
        organizational_unit=organizational_unit,
        email=email,
        custom_attributes=custom_attributes,
    )

    # 3. Build SAN extension
    san_ext = _build_san_extension(san_list)

    # 4. Determine Key Usages & EKU
    key_usage_ext, eku_ext = _get_key_usages_for_profile(cert_profile, custom_usages)

    # 5. Build PKCS#10 CSR
    csr_builder = x509.CertificateSigningRequestBuilder().subject_name(subject)
    if san_ext:
        csr_builder = csr_builder.add_extension(san_ext, critical=False)
    if eku_ext:
        csr_builder = csr_builder.add_extension(eku_ext, critical=False)

    # Hash algorithm selection (Ed25519 doesn't use pre-hashing)
    if key_algorithm == KeyAlgorithm.ED25519:
        csr = csr_builder.sign(private_key, algorithm=None)
    else:
        csr = csr_builder.sign(private_key, algorithm=hashes.SHA256())

    csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode("utf-8")

    # 6. Generate X.509 Certificate and Fullchain PEM
    now = datetime.now(timezone.utc)
    not_before = now - timedelta(minutes=5)
    not_after = now + timedelta(days=validity_days)

    import secrets
    serial_number = int.from_bytes(secrets.token_bytes(20), "big") >> 1

    cert_builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .public_key(private_key.public_key())
        .serial_number(serial_number)
        .not_valid_before(not_before)
        .not_valid_after(not_after)
    )

    # Add extensions to certificate
    if san_ext:
        cert_builder = cert_builder.add_extension(san_ext, critical=False)
    if key_usage_ext and key_algorithm != KeyAlgorithm.ED25519:
        cert_builder = cert_builder.add_extension(key_usage_ext, critical=True)
    if eku_ext:
        cert_builder = cert_builder.add_extension(eku_ext, critical=False)

    # Basic Constraints (End Entity cert)
    cert_builder = cert_builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True
    )

    # Subject Key Identifier
    cert_builder = cert_builder.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()), critical=False
    )

    # Authority & Issuer Configuration according to Issuance Mode
    intermediate_ca_pem = ""
    root_ca_pem = ""

    if issuance_mode == IssuanceMode.PUBLIC_LETS_ENCRYPT:
        # Public Let's Encrypt Staging / ACME template with Let's Encrypt Issuer representation
        issuer_name = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Let's Encrypt"),
            x509.NameAttribute(NameOID.COMMON_NAME, "R3"),
        ])
        cert_builder = cert_builder.issuer_name(issuer_name)
        
        # Self-signed representation for immediate validation + Certbot payload
        if key_algorithm == KeyAlgorithm.ED25519:
            cert = cert_builder.sign(private_key, algorithm=None)
        else:
            cert = cert_builder.sign(private_key, algorithm=hashes.SHA256())
            
        cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
        fullchain_pem = f"{cert_pem}\n# --- Let's Encrypt R3 Intermediate Simulated Authority ---\n{cert_pem}"

    elif issuance_mode == IssuanceMode.PRIVATE_LETS_ENCRYPT:
        # Generate Private Authority with Let's Encrypt styled Hierarchy (Root X1 -> Intermediate R3 -> Leaf)
        ca_private_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        ca_name = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, country[:2].upper() if country else "BR"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, f"{organization or 'Morfeu'} Private Let's Encrypt CA"),
            x509.NameAttribute(NameOID.COMMON_NAME, f"{organization or 'Morfeu'} Internal Authority R3"),
        ])
        
        ca_cert = (
            x509.CertificateBuilder()
            .subject_name(ca_name)
            .issuer_name(ca_name)
            .public_key(ca_private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(not_before)
            .not_valid_after(now + timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .sign(ca_private_key, hashes.SHA256())
        )

        cert_builder = cert_builder.issuer_name(ca_name)
        cert_builder = cert_builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_private_key.public_key()),
            critical=False,
        )

        if key_algorithm == KeyAlgorithm.ED25519:
            cert = cert_builder.sign(ca_private_key, algorithm=hashes.SHA256())
        else:
            cert = cert_builder.sign(ca_private_key, algorithm=hashes.SHA256())

        cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
        intermediate_ca_pem = ca_cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
        fullchain_pem = f"{cert_pem.strip()}\n\n{intermediate_ca_pem.strip()}\n"

    else:
        # Self-Signed Root Certificate
        cert_builder = cert_builder.issuer_name(subject)
        cert_builder = cert_builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(private_key.public_key()),
            critical=False,
        )

        if key_algorithm == KeyAlgorithm.ED25519:
            cert = cert_builder.sign(private_key, algorithm=None)
        else:
            cert = cert_builder.sign(private_key, algorithm=hashes.SHA256())

        cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
        fullchain_pem = cert_pem

    # 7. Extract Certificate Inspection Metadata
    fingerprint_sha256 = cert.fingerprint(hashes.SHA256()).hex().upper()
    fingerprint_sha256_formatted = ":".join(fingerprint_sha256[i : i + 2] for i in range(0, len(fingerprint_sha256), 2))
    
    fingerprint_sha1 = cert.fingerprint(hashes.SHA1()).hex().upper()
    fingerprint_sha1_formatted = ":".join(fingerprint_sha1[i : i + 2] for i in range(0, len(fingerprint_sha1), 2))

    # OpenSSL commands for quick verification and execution
    acme_command = f"certbot certonly --manual --preferred-challenges dns -d {','.join(common_names)} --csr cert_request.csr"
    openssl_verify_cmd = f"openssl x509 -in certificate.crt -text -noout"
    openssl_csr_cmd = f"openssl req -in request.csr -text -noout"

    return {
        "files": {
            "key": private_key_pem,
            "csr": csr_pem,
            "crt": cert_pem,
            "pem": fullchain_pem,
            "intermediate_ca": intermediate_ca_pem,
        },
        "metadata": {
            "primary_common_name": primary_cn,
            "all_common_names": common_names,
            "subject_dn": subject.rfc4514_string(),
            "issuer_dn": cert.issuer.rfc4514_string(),
            "serial_number_hex": hex(cert.serial_number)[2:].upper(),
            "serial_number_dec": str(cert.serial_number),
            "fingerprint_sha256": fingerprint_sha256_formatted,
            "fingerprint_sha1": fingerprint_sha1_formatted,
            "valid_from": not_before.isoformat(),
            "valid_to": not_after.isoformat(),
            "validity_days": validity_days,
            "key_algorithm": key_algorithm.value,
            "profile": cert_profile.value,
            "issuance_mode": issuance_mode.value,
            "san_list": san_list,
            "san_count": len(san_list),
            "is_encrypted_key": bool(key_password),
        },
        "guides": {
            "acme_certbot_command": acme_command,
            "openssl_verify_command": openssl_verify_cmd,
            "openssl_csr_command": openssl_csr_cmd,
            "nginx_snippet": (
                f"ssl_certificate /etc/ssl/{primary_cn}.pem;\n"
                f"ssl_certificate_key /etc/ssl/{primary_cn}.key;\n"
                f"ssl_protocols TLSv1.2 TLSv1.3;\n"
                f"ssl_ciphers HIGH:!aNULL:!MD5;"
            ),
        },
    }


def parse_csr_text(csr_pem: str) -> Dict[str, Any]:
    """Inspect and parse an arbitrary PEM-encoded CSR, extracting all attributes."""
    try:
        # Normalize CSR text
        clean_pem = csr_pem.strip()
        if "-----BEGIN CERTIFICATE REQUEST-----" not in clean_pem and "-----BEGIN NEW CERTIFICATE REQUEST-----" not in clean_pem:
            # Check if base64 only
            clean_pem = f"-----BEGIN CERTIFICATE REQUEST-----\n{clean_pem}\n-----END CERTIFICATE REQUEST-----"

        csr = x509.load_pem_x509_csr(clean_pem.encode("utf-8"))
        
        # Extract Subject attributes
        common_names = []
        country = None
        state = None
        locality = None
        organization = None
        organizational_unit = None
        email = None

        for attr in csr.subject:
            oid = attr.oid
            val = str(attr.value)
            if oid == NameOID.COMMON_NAME:
                common_names.append(val)
            elif oid == NameOID.COUNTRY_NAME:
                country = val
            elif oid == NameOID.STATE_OR_PROVINCE_NAME:
                state = val
            elif oid == NameOID.LOCALITY_NAME:
                locality = val
            elif oid == NameOID.ORGANIZATION_NAME:
                organization = val
            elif oid == NameOID.ORGANIZATIONAL_UNIT_NAME:
                organizational_unit = val
            elif oid == NameOID.EMAIL_ADDRESS:
                email = val

        # Extract SANs
        sans = []
        try:
            san_ext = csr.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            for name in san_ext.value:
                if isinstance(name, x509.DNSName):
                    sans.append({"type": "DNS", "value": name.value})
                elif isinstance(name, x509.IPAddress):
                    sans.append({"type": "IP", "value": str(name.value)})
                elif isinstance(name, x509.UniformResourceIdentifier):
                    sans.append({"type": "URI", "value": name.value})
                elif isinstance(name, x509.RFC822Name):
                    sans.append({"type": "EMAIL", "value": name.value})
                elif isinstance(name, x509.RegisteredID):
                    sans.append({"type": "RID", "value": name.value.dotted_string})
                elif isinstance(name, x509.OtherName):
                    sans.append({"type": "OTHERNAME", "value": name.value.decode("utf-8", errors="ignore"), "oid": name.type_id.dotted_string})
        except x509.ExtensionNotFound:
            pass

        # Public key info
        pub_key = csr.public_key()
        pub_info = "Unknown"
        if isinstance(pub_key, rsa.RSAPublicKey):
            pub_info = f"RSA {pub_key.key_size} bits"
        elif isinstance(pub_key, ec.EllipticCurvePublicKey):
            pub_info = f"ECDSA {pub_key.curve.name}"
        elif isinstance(pub_key, ed25519.Ed25519PublicKey):
            pub_info = "Ed25519"

        return {
            "valid": True,
            "is_signature_valid": csr.is_signature_valid,
            "subject_dn": csr.subject.rfc4514_string(),
            "common_names": common_names if common_names else ["localhost"],
            "country": country or "",
            "state": state or "",
            "locality": locality or "",
            "organization": organization or "",
            "organizational_unit": organizational_unit or "",
            "email": email or "",
            "public_key_type": pub_info,
            "sans": sans,
            "san_count": len(sans),
            "normalized_csr_pem": clean_pem,
        }
    except Exception as e:
        return {"valid": False, "error": f"Erro ao decodificar CSR: {str(e)}"}


def sign_pasted_csr(
    csr_pem: str,
    cert_profile: CertProfile = CertProfile.MUTUAL_TLS,
    issuance_mode: IssuanceMode = IssuanceMode.PRIVATE_LETS_ENCRYPT,
    validity_days: int = 90,
    custom_usages: Optional[Dict[str, bool]] = None,
) -> Dict[str, Any]:
    """
    Sign an uploaded/pasted CSR using Private Let's Encrypt CA or Self-Signed authority.
    Produces .crt and .pem fullchain bundles.
    """
    parsed = parse_csr_text(csr_pem)
    if not parsed.get("valid"):
        raise ValueError(parsed.get("error", "CSR inválido"))

    clean_pem = parsed.get("normalized_csr_pem", csr_pem)
    csr = x509.load_pem_x509_csr(clean_pem.encode("utf-8"))

    now = datetime.now(timezone.utc)
    not_before = now - timedelta(minutes=5)
    not_after = now + timedelta(days=validity_days)

    import secrets
    serial_number = int.from_bytes(secrets.token_bytes(20), "big") >> 1

    cert_builder = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .public_key(csr.public_key())
        .serial_number(serial_number)
        .not_valid_before(not_before)
        .not_valid_after(not_after)
    )

    # Copy extensions from CSR if present
    san_ext = None
    try:
        san_ext = csr.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        cert_builder = cert_builder.add_extension(san_ext.value, critical=False)
    except x509.ExtensionNotFound:
        # If no SAN in CSR, add CN as DNS SAN
        cns = parsed.get("common_names", [])
        if cns:
            san_items = []
            for c in cns:
                try:
                    ipaddress.ip_address(c)
                    san_items.append(x509.IPAddress(ipaddress.ip_address(c)))
                except ValueError:
                    san_items.append(x509.DNSName(c))
            if san_items:
                cert_builder = cert_builder.add_extension(x509.SubjectAlternativeName(san_items), critical=False)

    # Key Usages
    key_usage_ext, eku_ext = _get_key_usages_for_profile(cert_profile, custom_usages)
    if key_usage_ext and not isinstance(csr.public_key(), ed25519.Ed25519PublicKey):
        cert_builder = cert_builder.add_extension(key_usage_ext, critical=True)
    if eku_ext:
        cert_builder = cert_builder.add_extension(eku_ext, critical=False)

    cert_builder = cert_builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True
    )
    cert_builder = cert_builder.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(csr.public_key()), critical=False
    )

    intermediate_ca_pem = ""

    if issuance_mode == IssuanceMode.PRIVATE_LETS_ENCRYPT:
        ca_private_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        ca_name = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, parsed.get("country")[:2].upper() if parsed.get("country") else "BR"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, f"{parsed.get('organization') or 'Morfeu'} Private Let's Encrypt CA"),
            x509.NameAttribute(NameOID.COMMON_NAME, f"{parsed.get('organization') or 'Morfeu'} Internal Authority R3"),
        ])
        
        ca_cert = (
            x509.CertificateBuilder()
            .subject_name(ca_name)
            .issuer_name(ca_name)
            .public_key(ca_private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(not_before)
            .not_valid_after(now + timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .sign(ca_private_key, hashes.SHA256())
        )

        cert_builder = cert_builder.issuer_name(ca_name)
        cert_builder = cert_builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_private_key.public_key()),
            critical=False,
        )

        cert = cert_builder.sign(ca_private_key, algorithm=hashes.SHA256())
        cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
        intermediate_ca_pem = ca_cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
        fullchain_pem = f"{cert_pem.strip()}\n\n{intermediate_ca_pem.strip()}\n"

    else:
        # Public Let's Encrypt / Staging Simulated Authority
        ca_private_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        issuer_name = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Let's Encrypt"),
            x509.NameAttribute(NameOID.COMMON_NAME, "R3"),
        ])
        cert_builder = cert_builder.issuer_name(issuer_name)
        cert = cert_builder.sign(ca_private_key, algorithm=hashes.SHA256())
        cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
        fullchain_pem = cert_pem

    fingerprint_sha256 = cert.fingerprint(hashes.SHA256()).hex().upper()
    fingerprint_sha256_formatted = ":".join(fingerprint_sha256[i : i + 2] for i in range(0, len(fingerprint_sha256), 2))
    
    fingerprint_sha1 = cert.fingerprint(hashes.SHA1()).hex().upper()
    fingerprint_sha1_formatted = ":".join(fingerprint_sha1[i : i + 2] for i in range(0, len(fingerprint_sha1), 2))

    primary_cn = parsed.get("common_names", ["service"])[0]

    return {
        "files": {
            "key": "# [CHAVE PRIVADA EXISTENTE NÃO DISPONÍVEL NO CSR - MANTENHA SUA .KEY ORIGINAL]",
            "csr": clean_pem,
            "crt": cert_pem,
            "pem": fullchain_pem,
            "intermediate_ca": intermediate_ca_pem,
        },
        "metadata": {
            "primary_common_name": primary_cn,
            "all_common_names": parsed.get("common_names", []),
            "subject_dn": csr.subject.rfc4514_string(),
            "issuer_dn": cert.issuer.rfc4514_string(),
            "serial_number_hex": hex(cert.serial_number)[2:].upper(),
            "serial_number_dec": str(cert.serial_number),
            "fingerprint_sha256": fingerprint_sha256_formatted,
            "fingerprint_sha1": fingerprint_sha1_formatted,
            "valid_from": not_before.isoformat(),
            "valid_to": not_after.isoformat(),
            "validity_days": validity_days,
            "key_algorithm": parsed.get("public_key_type", "From CSR"),
            "profile": cert_profile.value,
            "issuance_mode": issuance_mode.value,
            "san_list": parsed.get("sans", []),
            "san_count": len(parsed.get("sans", [])),
            "is_from_pasted_csr": True,
        },
        "guides": {
            "acme_certbot_command": f"certbot certonly --manual --preferred-challenges dns -d {','.join(parsed.get('common_names', [primary_cn]))} --csr cert_request.csr",
            "openssl_verify_command": "openssl x509 -in certificate.crt -text -noout",
            "openssl_csr_command": "openssl req -in request.csr -text -noout",
            "nginx_snippet": (
                f"ssl_certificate /etc/ssl/{primary_cn}.pem;\n"
                f"ssl_certificate_key /etc/ssl/{primary_cn}.key;\n"
                f"ssl_protocols TLSv1.2 TLSv1.3;\n"
                f"ssl_ciphers HIGH:!aNULL:!MD5;"
            ),
        },
    }


def parse_cert_text(cert_pem: str) -> Dict[str, Any]:
    """Inspect and parse an arbitrary PEM-encoded X.509 certificate."""
    try:
        cert = x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))
        
        sans = []
        try:
            san_ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            for name in san_ext.value:
                if isinstance(name, x509.DNSName):
                    sans.append({"type": "DNS", "value": name.value})
                elif isinstance(name, x509.IPAddress):
                    sans.append({"type": "IP", "value": str(name.value)})
                elif isinstance(name, x509.UniformResourceIdentifier):
                    sans.append({"type": "URI", "value": name.value})
                elif isinstance(name, x509.RFC822Name):
                    sans.append({"type": "EMAIL", "value": name.value})
        except x509.ExtensionNotFound:
            pass

        sha256 = cert.fingerprint(hashes.SHA256()).hex().upper()
        sha256_fmt = ":".join(sha256[i : i + 2] for i in range(0, len(sha256), 2))

        return {
            "valid": True,
            "subject_dn": cert.subject.rfc4514_string(),
            "issuer_dn": cert.issuer.rfc4514_string(),
            "serial_hex": hex(cert.serial_number)[2:].upper(),
            "fingerprint_sha256": sha256_fmt,
            "not_before": cert.not_valid_before_utc.isoformat(),
            "not_after": cert.not_valid_after_utc.isoformat(),
            "sans": sans,
        }
    except Exception as e:
        return {"valid": False, "error": str(e)}


def create_bundle_zip(
    filename_base: str,
    key_pem: str,
    csr_pem: str,
    crt_pem: str,
    pem_fullchain: str,
    readme_content: Optional[str] = None,
) -> bytes:
    """Pack all PKI files into an in-memory ZIP archive."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr(f"{filename_base}.key", key_pem)
        z.writestr(f"{filename_base}.csr", csr_pem)
        z.writestr(f"{filename_base}.crt", crt_pem)
        z.writestr(f"{filename_base}.pem", pem_fullchain)
        
        default_readme = (
            f"=== AegisLattice PKI Artifacts Bundle ===\n"
            f"Generated: {datetime.now(timezone.utc).isoformat()}\n\n"
            f"Files included:\n"
            f"- {filename_base}.key : Private Key (KEEP SECURE!)\n"
            f"- {filename_base}.csr : PKCS#10 Certificate Signing Request\n"
            f"- {filename_base}.crt : X.509 End-Entity Certificate\n"
            f"- {filename_base}.pem : Fullchain Certificate Bundle\n\n"
            f"Usage Instructions:\n"
            f"For Nginx / Apache / Envoy / Traefik mTLS:\n"
            f"  ssl_certificate      /path/to/{filename_base}.pem;\n"
            f"  ssl_certificate_key  /path/to/{filename_base}.key;\n"
        )
        z.writestr("README_CERTIFICATE_USAGE.txt", readme_content or default_readme)

    buf.seek(0)
    return buf.getvalue()
