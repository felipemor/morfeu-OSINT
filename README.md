# 🛡️ morfeusec OSINT — Enterprise Offensive Intelligence & Autonomous Pentesting Platform

<div align="center">

![morfeusec OSINT Logo](frontend/public/morfeusec-logo.png)

**Enterprise-Grade Perimeter Reconnaissance, Autonomous Mobile Pentest (OWASP MASVS v2.0) & Threat Exposure Management**

[![FastAPI](https://img.shields.io/badge/FastAPI-0.110.0-009688.svg?style=flat&logo=fastapi)](https://fastapi.tiangolo.com)
[![Next.js](https://img.shields.io/badge/Next.js-14.2-black.svg?style=flat&logo=next.js)](https://nextjs.org/)
[![Python](https://img.shields.io/badge/Python-3.11%2B-blue.svg?style=flat&logo=python)](https://python.org)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED.svg?style=flat&logo=docker)](https://docker.com)
[![OWASP MASVS](https://img.shields.io/badge/OWASP-MASVS%20v2.0-orange.svg)](https://mas.owasp.org/MASVS/)
[![License](https://img.shields.io/badge/License-Proprietary%20Enterprise-red.svg)]()

</div>

---

## 🌟 Executive Overview

**morfeusec OSINT** is an audit-grade cybersecurity platform built to bridge the gap between advanced **Perimeter Reconnaissance (OSINT)**, **Autonomous Ethical Hacker Mobile Pentesting (Android & iOS)**, and **Continuous Security Validation (BACEN, NIST SP 800-115, CIS Controls, ISO 27001)**.

Designed to meet the stringent auditing criteria of **Big4 (PwC, Deloitte, EY, KPMG)** and the world-class UX standards of **Google and Microsoft Security**, morfeusec OSINT provides real-time multi-vector exposure insights with automated executive and technical remediation reporting.

---

## 🚀 Core Platform Modules

### 1. 📱 Autonomous Mobile Application Pentesting (`/mobile-pentest`)
A complete ethical hacker static (SAST) and dynamic (DAST) assessment engine for mobile applications:
- **Multi-Package Batch Upload**: Simultaneous drag-and-drop processing of multiple `.apk` (Android) and `.ipa` (iOS) binaries.
- **AndroidManifest & Info.plist Inspection**: Detection of dangerous exported activities, broadcast receivers, vulnerable deep link intent filters, content providers, `android:debuggable="true"`, `android:allowBackup="true"`, and `android:usesCleartextTraffic="true"`.
- **Hardcoded Secret & Credential Extractor**: Regex heuristic matching for Google API Keys (`AIza...`), AWS Access Keys (`AKIA...`), Firebase databases, Stripe private keys, and JWT tokens.
- **Insecure Cryptography & Storage Audit (CWE-327 / CWE-328)**: Identifies weak algorithms (MD5, SHA-1) and insecure encryption modes (`AES/ECB`).
- **Network Security & SSL Pinning (CWE-295 / CWE-319)**: Identifies lack of TLS certificate pinning, insecure TrustManagers, and cleartext HTTP endpoints.
- **Anti-Reverse Engineering Resilience (MASVS-RESILIENCE)**: Validates resistance against Root/Jailbreak, Frida dynamic hooks, and bytecode tampering.
- **Audit-Grade Reports Export**:
  - 📄 **Executive & Technical PDF Report in Português (Brasil)**
  - 📄 **Executive & Technical PDF Report in English (US)**
  - 📊 **Multi-sheet Audit Workbook (.xlsx)** with vulnerability matrices and permission catalogs.

### 2. 🌐 Perimeter Reconnaissance & OSINT Intelligence (`/osint`)
Inspired by advanced recon suites (`reNgine` / `equip.md`):
- **DNS Zone Intelligence & DoH**: Query `A`, `AAAA`, `MX`, `TXT`, `NS`, `CAA`, and `SOA` via DNS-over-HTTPS (Cloudflare / Google DoH).
- **Certificate Transparency (CT Logs)**: Historical and active subdomain discovery querying `crt.sh` and live TLS Subject Alternative Names (SANs).
- **ASN & Cloud Infrastructure Detection**: Reverse DNS (PTR), ASN organization, country, city, and automatic cloud/CDN identification (**Akamai Intelligent Edge**, **AWS**, **Cloudflare**, **Azure**, **GCP**).
- **Web & WAF Fingerprinting**: Identifies WAF signatures (`AkamaiGHost`, `cf-ray`, `x-amz-cf-id`) and security headers (`HSTS`, `CSP`, `X-Frame-Options`, `X-Content-Type-Options`).
- **E-mail Security & Anti-Spoofing Posture**: Evaluates **SPF**, **DMARC** (`p=reject`, `p=quarantine`, `p=none`), and **MX** records against phishing risks.
- **Google Dorking Engine**: Automated dork generator for sensitive files (`.env`, `.git`, `.sql`), admin dashboards, Swagger/OpenAPI docs, and directory listings.
- **Cloud Storage & S3 Bucket Auditor**: Probes AWS S3, GCP Storage, and Azure Blob permutations for open public access.

### 3. 🛡️ 32 Security Controls Testing (`/security-controls`)
Auditable validation engine covering 32 continuous security checks based on BACEN and CIS Controls:
- **Transport Security**: TLS 1.3 enforcement, ECDHE cipher suites, HSTS preloading.
- **API & Web Hardening**: CORS wildcard prevention, Rate Limiting, HTTP verb restriction (`TRACE`/`TRACK`), Server banner suppression.
- **Sensitive Asset Exposure**: Automated detection of exposed `.env`, `.git`, `.aws/credentials`, and backup dumps.
- **Real-time Excel Audit Trail (.xlsx)** and **Formal PDF Security Validation Report**.

### 4. 📊 Unified Control Center & Threat Surface
- **Cross-Module Threat Synchronization**: Mobile pentest findings, OSINT discoveries, and security control results feed directly into **Dashboard**, **Attack Surface**, and **Reports**.
- **QR Code & Corporate Smartphone 2FA**: Zero-trust session validation using time-based QR authentication.

---

## 🏗️ Architecture

```text
┌────────────────────────────────────────────────────────────────────────────┐
│                              morfeusec OSINT                               │
│                   ENTERPRISE OFFENSIVE INTELLIGENCE HUD                    │
└────────────────────────────────────────────────────────────────────────────┘
                                      │
        ┌─────────────────────────────┼─────────────────────────────┐
        ▼                             ▼                             ▼
┌──────────────────┐        ┌──────────────────┐        ┌──────────────────┐
│  OSINT Perimeter │        │  Mobile Pentest  │        │ Security Controls│
│  Intelligence    │        │  Engine (MASVS)  │        │ (BACEN / CIS 32) │
├──────────────────┤        ├──────────────────┤        ├──────────────────┤
│ • DoH DNS & CAA  │        │ • APK / IPA SAST │        │ • TLS 1.3 / HSTS │
│ • crt.sh CT Logs │        │ • Manifest Audit │        │ • CORS / Headers │
│ • Akamai / WAF   │        │ • Secret Finder  │        │ • Env/Git Leaks  │
│ • Google Dorks   │        │ • SSL Pinning    │        │ • Rate Limiting  │
│ • Cloud S3 Prober│        │ • Anti-Reversing │        │ • Audit Trail    │
└──────────────────┘        └──────────────────┘        └──────────────────┘
        │                             │                             │
        └─────────────────────────────┼─────────────────────────────┘
                                      ▼
             ┌──────────────────────────────────────────────────┐
             │       FastAPI Backend & Async Python Core        │
             │       PostgreSQL 16 + Redis 7 + Structlog        │
             │       ReportLab (PDF) + OpenPyXL (Excel .xlsx)   │
             └──────────────────────────────────────────────────┘
```

---

## ⚡ Quick Start

### 1. Run with Docker Compose (Recommended)

```bash
docker compose up -d
```

### 2. Run Locally (Development Mode)

#### Backend (FastAPI):
```bash
cd backend
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

#### Frontend (Next.js):
```bash
cd frontend
npm install
npm run dev
```

---

## 🔗 Platform Navigation & Endpoints

| Portal Section | URL | Description |
|---|---|---|
| **Control Center Dashboard** | `http://localhost:3000/dashboard` | Unified Executive KPI & Threat Posture |
| **Mobile Pentest (APK & iOS)** | `http://localhost:3000/mobile-pentest` | Multi-APK SAST/DAST & PDF/XLSX Reports |
| **OSINT Intelligence** | `http://localhost:3000/osint` | DNS, Certs, Akamai/WAF, Dorks & S3 |
| **Controles de Segurança** | `http://localhost:3000/security-controls` | 32 BACEN / CIS Controls & PDF Audit |
| **Attack Surface Mapping** | `http://localhost:3000/attack-surface` | Perimeter Asset & Vulnerability Graph |
| **Reports Center** | `http://localhost:3000/reports` | Multi-format Executive Dossiers |
| **Interactive API Docs (Swagger)** | `http://localhost:8000/docs` | OpenAPI 3.0 Interactive Documentation |

---

## 🧪 Automated Testing

morfeusec OSINT includes a comprehensive test suite covering all services and API endpoints:

```bash
cd backend
python -m pytest tests -vv
```

*Current Test Suite Status: **47/47 passing (100% success rate)**.*

---

## 📜 Compliance & Standards

- **OWASP MASVS v2.0** (Mobile Application Security Verification Standard)
- **OWASP Mobile Top 10**
- **OWASP Web Top 10 (2021)**
- **BACEN Resolução CMN nº 4.893 / Resolução BCB nº 85**
- **NIST SP 800-115** (Technical Guide to Information Security Testing and Assessment)
- **CIS Controls v8**

---

<div align="center">

**morfeusec OSINT** © 2026. Aplicação escrita e desenvolvida por **Felipe Costa** — [`fsec.costa@gmail.com`](mailto:fsec.costa@gmail.com).

</div>
