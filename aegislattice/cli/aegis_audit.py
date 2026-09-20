#!/usr/bin/env python3
"""
AegisLattice CLI — Standalone Post-Quantum Cryptography & CBOM Audit Tool
Usage:
  python aegis_audit.py scan <host> [--port 443] [--json]
  python aegis_audit.py cbom <host> [--port 443] [--output cbom.json]
"""
import argparse
import json
import socket
import ssl
import sys
from datetime import datetime, timezone

def inspect_tls(host: str, port: int = 443) -> dict:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    with socket.create_connection((host, port), timeout=8) as sock:
        with context.wrap_socket(sock, server_hostname=host) as ssock:
            tls_version = ssock.version()
            cipher_info = ssock.cipher()
            cipher_suite = cipher_info[0] if cipher_info else "UNKNOWN"
            protocol = cipher_info[1] if cipher_info and len(cipher_info) > 1 else tls_version
            key_bits = cipher_info[2] if cipher_info and len(cipher_info) > 2 else 0

            cert = ssock.getpeercert(binary_form=True)

    # Cryptographic posture evaluation
    pqc_supported = "KYBER" in cipher_suite.upper() or "MLKEM" in cipher_suite.upper() or "ML-KEM" in cipher_suite.upper()
    
    if pqc_supported:
        posture = "QUANTUM_RESISTANT"
        risk_score = 0.0
    elif "ECDHE" in cipher_suite or "DHE" in cipher_suite:
        posture = "HARVEST_NOW_DECRYPT"
        risk_score = 65.0
    elif "RSA" in cipher_suite or "CBC" in cipher_suite or "RC4" in cipher_suite:
        posture = "CRITICAL_VULNERABLE"
        risk_score = 95.0
    else:
        posture = "UNKNOWN"
        risk_score = 50.0

    return {
        "host": host,
        "port": port,
        "tls_version": tls_version,
        "cipher_suite": cipher_suite,
        "key_exchange": "ECDHE / Classical" if "ECDHE" in cipher_suite else "Classical RSA",
        "key_bits": key_bits,
        "posture": posture,
        "risk_score": risk_score,
        "pqc_supported": pqc_supported,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "remediation": "Migrate to Hybrid Key Encapsulation Mechanism (X25519 + ML-KEM-768 per FIPS 203)." if not pqc_supported else "Post-quantum posture verified."
    }

def generate_cbom(host: str, port: int = 443) -> dict:
    audit = inspect_tls(host, port)
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:aegislattice-cbom-{host}-{port}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": [{"vendor": "AegisLattice", "name": "aegis-audit", "version": "1.0.0"}],
            "component": {
                "type": "service",
                "name": host,
                "cryptoProperties": {
                    "assetType": "protocol",
                    "protocol": audit["tls_version"],
                    "cipherSuite": audit["cipher_suite"],
                    "classicalSecurityBits": audit["key_bits"],
                    "quantumSecurityLevel": 3 if audit["pqc_supported"] else 0,
                    "algorithmProperties": {
                        "name": audit["cipher_suite"],
                        "cryptoFunctions": ["key-exchange", "encryption", "mac"]
                    }
                }
            }
        },
        "components": [
            {
                "type": "cryptographic-asset",
                "name": "TLS Key Encapsulation / Exchange",
                "cryptoProperties": {
                    "assetType": "algorithm",
                    "algorithmProperties": {
                        "name": audit["key_exchange"],
                        "pqcClassification": "POST_QUANTUM_SECURE" if audit["pqc_supported"] else "VULNERABLE_HNDL"
                    }
                }
            }
        ]
    }

def main():
    parser = argparse.ArgumentParser(description="AegisLattice Post-Quantum Cryptography Auditor")
    subparsers = parser.add_subparsers(dest="subcommand", required=True)

    scan_parser = subparsers.add_parser("scan", help="Scan crypto posture and HNDL risk")
    scan_parser.add_argument("host", help="Target hostname or IP")
    scan_parser.add_argument("--port", type=int, default=443, help="Port (default: 443)")
    scan_parser.add_argument("--json", action="store_true", help="Output JSON format")

    cbom_parser = subparsers.add_parser("cbom", help="Export CycloneDX 1.6 CBOM")
    cbom_parser.add_argument("host", help="Target hostname or IP")
    cbom_parser.add_argument("--port", type=int, default=443, help="Port (default: 443)")
    cbom_parser.add_argument("--output", help="Output file path (default: stdout)")

    args = parser.parse_args()

    if args.subcommand == "scan":
        result = inspect_tls(args.host, args.port)
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print("=" * 60)
            print(f" AegisLattice Crypto Posture Audit: {result['host']}:{result['port']}")
            print("=" * 60)
            print(f" TLS Version:     {result['tls_version']}")
            print(f" Cipher Suite:    {result['cipher_suite']}")
            print(f" Posture:         {result['posture']}")
            print(f" Risk Score:      {result['risk_score']}/100")
            print(f" PQC Ready:       {'YES' if result['pqc_supported'] else 'NO (HNDL Vulnerable)'}")
            print(f" Remediation:     {result['remediation']}")
            print("=" * 60)

    elif args.subcommand == "cbom":
        cbom = generate_cbom(args.host, args.port)
        cbom_json = json.dumps(cbom, indent=2)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(cbom_json)
            print(f"CBOM saved to {args.output}")
        else:
            print(cbom_json)

if __name__ == "__main__":
    main()
