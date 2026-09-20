"""
FRAUDINTEL — Digital Fraud Intelligence & Investigation Platform
Seed Data: Enterprise Cases, Entities, Indicators, Boletos, and Default Demo Investigation.
"""

from datetime import datetime, timezone, timedelta
import hashlib
import uuid

def _ts(delta_days: int = 0, delta_hours: int = 0, delta_minutes: int = 0) -> str:
    dt = datetime.now(timezone.utc) - timedelta(days=delta_days, hours=delta_hours, minutes=delta_minutes)
    return dt.isoformat()

def _sha256(val: str) -> str:
    return hashlib.sha256(val.encode()).hexdigest()

# ── DEMO INVESTIGATION: FRD-2026-0001 ──────────────────────────────────────────

DEMO_INVESTIGATION_CASE = {
    "id": "FRD-2026-0001",
    "title": "Campanha de Impersonação de Marca & Gateway Clonado",
    "target_asset": "https://nubank-segunda-via-portal.com",
    "brand_victim": "Nubank",
    "case_type": "BRAND_IMPERSONATION",
    "severity": "CRITICAL",
    "status": "INVESTIGATING",
    "owner": "Felipe Moreira Costa (Lead Fraud Architect)",
    "created_at": _ts(delta_days=2, delta_hours=4),
    "updated_at": _ts(delta_minutes=15),
    "risk_score": {
        "score": 88,
        "grade": "CRITICAL",
        "confidence": 92.5,
        "factors": [
            {"factor": "Alta Similaridade com Marca Oficial (94%)", "points": 25, "category": "BRAND"},
            {"factor": "Domínio Registrado há Apenas 8 Dias", "points": 20, "category": "DOMAIN_AGE"},
            {"factor": "Hospedagem em Provedor Bulletproof / Fast-Flux", "points": 18, "category": "INFRASTRUCTURE"},
            {"factor": "Certificado SSL Emitido Fora do Padrão Corporativo", "points": 10, "category": "CERTIFICATE"},
            {"factor": "Correlação com IP Usado no Caso #FRD-2025-0841", "points": 15, "category": "CORRELATION"}
        ]
    },
    "executive_summary": (
        "Investigação iniciada após detecção de domínio lookalike ativo (nubank-segunda-via-portal.com) "
        "operando portal falso de emissão de boletos e captura de credenciais bancárias. "
        "A infraestrutura identificada correlaciona-se diretamente com campanhas de phishing observadas anteriormente no setor financeiro."
    ),
    "entities": [
        {"id": "ENT-DOM-01", "type": "Domain", "name": "nubank-segunda-via-portal.com", "role": "Vetor de Ataque"},
        {"id": "ENT-IP-01", "type": "IP", "name": "185.220.101.42", "role": "Hospedagem Bulletproof (Rússia)"},
        {"id": "ENT-ASN-01", "type": "ASN", "name": "AS49453 - Global Telehouse Host", "role": "Sistema Autônomo"},
        {"id": "ENT-CERT-01", "type": "Certificate", "name": "Let's Encrypt Authority X3 (CN=nubank-segunda-via-portal.com)", "role": "SSL/TLS Falso"},
        {"id": "ENT-CNPJ-01", "type": "CNPJ", "name": "36.126.857/0001-49 - NU COBRANCAS LTDA", "role": "Beneficiário Fraudulento"},
        {"id": "ENT-BRAND-01", "type": "Brand", "name": "Nubank (Nu Pagamentos S.A.)", "role": "Marca Vítima"}
    ],
    "findings": [
        {
            "id": "FND-01",
            "type": "IMPERSONATION_PHISHING",
            "classification": "EVIDENCE",
            "title": "Similaridade Fonética e Visual de Marca (94%)",
            "description": "O domínio utiliza combinação do nome da marca com sufixos comumente usados em estelionato ('segunda-via-portal').",
            "rule_id": "RULE_DOMAIN_IMPERSONATION",
            "evidence_id": "EV-000101",
            "confidence": 95
        },
        {
            "id": "FND-02",
            "type": "INFRASTRUCTURE_ANOMALY",
            "classification": "CORRELATION",
            "title": "Hospedagem Compartilhada com Incidente Prévio",
            "description": "O endereço IP 185.220.101.42 foi observado hospedando phishings no caso #FRD-2025-0841.",
            "rule_id": "RULE_INFRASTRUCTURE_CORRELATION",
            "evidence_id": "EV-000102",
            "confidence": 90
        },
        {
            "id": "FND-03",
            "type": "FINANCIAL_FRAUD",
            "classification": "INDICATOR",
            "title": "Emissão de Boletos Adulterados com CNPJ Lookalike",
            "description": "A página injeta código de barras com beneficiário apontando para CNPJ clone recém-criado na Receita Federal.",
            "rule_id": "RULE_BENEFICIARY_MISMATCH",
            "evidence_id": "EV-000103",
            "confidence": 88
        }
    ],
    "hypotheses": [
        {
            "id": "HYP-01",
            "statement": "Operação de grupo criminoso organizado especializado em Smishing e falso SAC bancário.",
            "status": "HIGH_PROBABILITY",
            "supporting_evidences": ["EV-000101", "EV-000102", "EV-000103"]
        }
    ],
    "insights": [
        {
            "id": "INS-01",
            "headline": "Campanha ativa de phishing com infraestrutura resiliente e gateway de pagamento espelhado.",
            "why_it_matters": "Clientes que buscam negociar dívidas no Google estão sendo redirecionados para este portal fraudulento e efetuando pagamentos via PIX/Boleto para o CNPJ infrator.",
            "supporting_evidence": ["EV-000101", "EV-000102", "EV-000103"],
            "confidence": 92.5,
            "risk_level": "CRITICAL",
            "affected_entities": ["nubank-segunda-via-portal.com", "36.126.857/0001-49", "185.220.101.42"],
            "recommended_action": "Executar takedown multicanal imediato (Google SafeBrowsing, Registrar, Cloudflare Abuse) e oficiar a Receita Federal / BACEN."
        }
    ],
    "timeline": [
        {"timestamp": _ts(delta_days=8), "event": "Registro do domínio no Registrar NameCheap por serviço de anonimização (WhoisGuard)."},
        {"timestamp": _ts(delta_days=7, delta_hours=12), "event": "Emissão de Certificado TLS Let's Encrypt para o domínio."},
        {"timestamp": _ts(delta_days=5), "event": "Primeiro apontamento DNS para IP 185.220.101.42 (Rússia / AS49453)."},
        {"timestamp": _ts(delta_days=2, delta_hours=4), "event": "Detecção automática pelo radar de Threat Intelligence do FRAUDINTEL."},
        {"timestamp": _ts(delta_days=1, delta_hours=8), "event": "Coleta de evidência criptográfica SHA-256 e análise pericial do código-fonte da página."},
        {"timestamp": _ts(delta_hours=2), "event": "Despacho do pacote de Takedown para 5 autoridades e registrars com SLA de neutralização ativo."}
    ],
    "evidences": [
        {
            "id": "EV-000101",
            "type": "DOM_SNAPSHOT",
            "source": "Passive Crawler Engine",
            "collected_at": _ts(delta_days=2),
            "collector": "FRAUDINTEL-Probe-Worker-01",
            "sha256": _sha256("nubank-segunda-via-portal.com|HTML_BODY|2026"),
            "description": "Cópia integral do código HTML e formulário de captura de dados da página fraudulenta."
        },
        {
            "id": "EV-000102",
            "type": "DNS_CERT_RECORD",
            "source": "CT-Log & DNS Resolver",
            "collected_at": _ts(delta_days=2),
            "collector": "FRAUDINTEL-DNS-Worker",
            "sha256": _sha256("185.220.101.42|LETS_ENCRYPT_FINGERPRINT"),
            "description": "Registro de emissão de certificado TLS e histórico de resolução DNS para IP 185.220.101.42."
        },
        {
            "id": "EV-000103",
            "type": "FINANCIAL_ARTIFACT",
            "source": "Boleto Analyzer Module",
            "collected_at": _ts(delta_days=1),
            "collector": "Felipe Moreira Costa",
            "sha256": _sha256("BOLETO_SAMPLE_NU_COBRANCAS_36126857000149"),
            "description": "Boleto bancário falso gerado pela página com código de barras apontando para conta PJ receptora."
        }
    ],
    "takedown": {
        "status": "DISPATCHED_IN_PROGRESS",
        "sla_total_hours": 24,
        "sla_started_at": _ts(delta_hours=2, delta_minutes=15),
        "sla_deadline": (datetime.now(timezone.utc) + timedelta(hours=21, minutes=45)).isoformat(),
        "tickets": {
            "google_safebrowsing": "GSB-2026-881924",
            "microsoft_smartscreen": "MSS-994120",
            "registrar_abuse": "REG-ABUSE-7712",
            "cloudflare_abuse": "CF-TICKET-662301",
            "cert_revocation": "CRL-REV-5519"
        },
        "probe_live_status": {
            "is_online": True,
            "http_status": 200,
            "last_checked_at": _ts(delta_minutes=2),
            "status_label": "🟢 MONITORANDO RESPOSTA DO HOST (Takedown em Andamento)"
        }
    }
}

# ── 20 ENTERPRISE CASES DATASET ────────────────────────────────────────────────

SEED_CASES = [
    DEMO_INVESTIGATION_CASE,
    {
        "id": "FRD-2026-0002",
        "title": "Adulteração de Linha Digitável em Boletos de Fornecedores",
        "target_asset": "Boleto Fornecedor Indústria Peças S.A.",
        "brand_victim": "Indústria Geral S.A.",
        "case_type": "BOLETO_FRAUD",
        "severity": "CRITICAL",
        "status": "TRIAGE",
        "owner": "Ana Paula Ribeiro",
        "created_at": _ts(delta_days=3),
        "updated_at": _ts(delta_hours=1),
        "risk_score": {"score": 92, "grade": "CRITICAL", "confidence": 96.0, "factors": [{"factor": "Beneficiário Divergente do Contrato Social", "points": 35, "category": "BENEFICIARY"}]},
        "executive_summary": "Boleto com valor de R$ 148.000,00 recebido por e-mail com alteração de código de barras direcionando fundos para conta de terceiro em banco digital.",
        "entities": [{"id": "ENT-BOL-02", "type": "Boleto", "name": "34191.79001 01043.510047 91020.150008 8 98450014800000", "role": "Documento Fraude"}],
        "findings": [], "hypotheses": [], "insights": [], "timeline": [], "evidences": []
    },
    {
        "id": "FRD-2026-0003",
        "title": "Phishing com Ataque Homóglifo Cirílico (IDN Spoofing)",
        "target_asset": "https://xn--itau-pza.com.br (itaù.com.br)",
        "brand_victim": "Banco Itaú",
        "case_type": "HOMOGLYPH_PHISHING",
        "severity": "HIGH",
        "status": "INVESTIGATING",
        "owner": "Marcos Vinicius Silva",
        "created_at": _ts(delta_days=4),
        "updated_at": _ts(delta_hours=3),
        "risk_score": {"score": 79, "grade": "HIGH", "confidence": 89.0, "factors": [{"factor": "Uso de Caracteres Unicode Especiais", "points": 30, "category": "HOMOGLYPH"}]},
        "executive_summary": "Domínio IDN registrado com caractere acentuado imperceptível aos olhos do usuário direcionando para página clone de internet banking.",
        "entities": [], "findings": [], "hypotheses": [], "insights": [], "timeline": [], "evidences": []
    },
    {
        "id": "FRD-2026-0004",
        "title": "Falsa Central Telefônica 0800 com Domínio de Suporte Spoofado",
        "target_asset": "https://central-atendimento-inter-0800.site",
        "brand_victim": "Banco Inter",
        "case_type": "CALL_CENTER_PHISHING",
        "severity": "CRITICAL",
        "status": "ESCALATED",
        "owner": "Felipe Moreira Costa",
        "created_at": _ts(delta_days=5),
        "updated_at": _ts(delta_hours=5),
        "risk_score": {"score": 95, "grade": "CRITICAL", "confidence": 98.0, "factors": [{"factor": "Distribuição de Malware APK Falso Módulo", "points": 40, "category": "MALWARE"}]},
        "executive_summary": "Anúncio patrocinado promovendo falso suporte telefônico que induz vítimas a instalarem arquivo APK espião para roubo de sessão bancária.",
        "entities": [], "findings": [], "hypotheses": [], "insights": [], "timeline": [], "evidences": []
    },
    {
        "id": "FRD-2026-0005",
        "title": "Fraude de Empréstimo com Cobrança de Taxa Prévia de Cartório",
        "target_asset": "https://mercadolivre-credito-aprovado.net",
        "brand_victim": "Mercado Livre",
        "case_type": "LOAN_FEE_FRAUD",
        "severity": "HIGH",
        "status": "RESOLVED",
        "owner": "Juliana Mendes",
        "created_at": _ts(delta_days=10),
        "updated_at": _ts(delta_days=1),
        "risk_score": {"score": 74, "grade": "HIGH", "confidence": 85.0, "factors": [{"factor": "Cobrança Ilícita de Taxa Prévia", "points": 25, "category": "REGULATORY"}]},
        "executive_summary": "Página falsa simulando liberação imediata de crédito exigindo depósito de R$ 350,00 via PIX sob pretexto de 'Seguro Fiança Cartorial'.",
        "entities": [], "findings": [], "hypotheses": [], "insights": [], "timeline": [], "evidences": []
    }
]

# Generate cases up to 20
for idx in range(6, 21):
    case_types = ["BRAND_IMPERSONATION", "BOLETO_FRAUD", "TYPOSQUATTING", "PHISHING_LOGIN_CLONE", "INVOICE_INTERCEPTION"]
    severities = ["CRITICAL", "HIGH", "MEDIUM"]
    c_type = case_types[idx % len(case_types)]
    sev = severities[idx % len(severities)]
    score = 65 + (idx * 2) % 32
    
    SEED_CASES.append({
        "id": f"FRD-2026-{str(idx).zfill(4)}",
        "title": f"Investigação de Fraude Digital Corporativa #{idx} - {c_type.replace('_', ' ')}",
        "target_asset": f"https://portal-servicos-financeiros-{idx}.com",
        "brand_victim": "Empresa Corporativa Homologada S.A.",
        "case_type": c_type,
        "severity": sev,
        "status": "INVESTIGATING" if idx % 2 == 0 else "RESOLVED",
        "owner": "FRAUDINTEL Investigator Team",
        "created_at": _ts(delta_days=idx * 2),
        "updated_at": _ts(delta_hours=idx),
        "risk_score": {
            "score": score,
            "grade": sev,
            "confidence": 88.0 + (idx % 10),
            "factors": [
                {"factor": "Indicador Técnico Identificado na Borda", "points": 20, "category": "NETWORK"},
                {"factor": "Divergência de Padrão Histórico", "points": 15, "category": "ANOMALY"}
            ]
        },
        "executive_summary": f"Caso #{idx} autônomo monitorando vetores de {c_type.lower()} e correlações perimétricas de infraestrutura.",
        "entities": [], "findings": [], "hypotheses": [], "insights": [], "timeline": [], "evidences": []
    })

# ── DETECTION RULES CATALOG ───────────────────────────────────────────────────

DETECTION_RULES_CATALOG = [
    {
        "id": "RULE_DOMAIN_IMPERSONATION",
        "name": "Impersonação de Marca & Typosquatting",
        "description": "Detecta registros de domínios com similaridade fonética/ortográfica > 80% em relação à marca corporativa.",
        "severity": "CRITICAL",
        "confidence": 92,
        "weight": 25,
        "enabled": True,
        "category": "BRAND_PROTECTION"
    },
    {
        "id": "RULE_SUSPICIOUS_BOLETO",
        "name": "Adulteração de Linha Digitável e Beneficiário",
        "description": "Identifica divergência entre o CNPJ do beneficiário registrado no banco emissor e a Razão Social acordada.",
        "severity": "CRITICAL",
        "confidence": 96,
        "weight": 35,
        "enabled": True,
        "category": "FINANCIAL_FRAUD"
    },
    {
        "id": "RULE_BENEFICIARY_MISMATCH",
        "name": "Divergência Crítica de Beneficiário (CNPJ / Conta)",
        "description": "Flagrante onde o recebedor do pagamento é uma entidade desvinculada ou MEI sem relação contratual.",
        "severity": "CRITICAL",
        "confidence": 94,
        "weight": 30,
        "enabled": True,
        "category": "FINANCIAL_FRAUD"
    },
    {
        "id": "RULE_INFRASTRUCTURE_CORRELATION",
        "name": "Infraestrutura Correlacionada a Ataques Anteriores",
        "description": "Alerta quando o IP, ASN ou Nameserver do novo domínio coincide com infraestrutura de casos investigados.",
        "severity": "HIGH",
        "confidence": 88,
        "weight": 20,
        "enabled": True,
        "category": "THREAT_INTEL"
    },
    {
        "id": "RULE_SUSPICIOUS_DOMAIN_AGE",
        "name": "Domínio Criado Recentemente (< 30 Dias)",
        "description": "Domínios com menos de 30 dias de registro operando páginas de checkout ou formulários de autenticação.",
        "severity": "HIGH",
        "confidence": 85,
        "weight": 18,
        "enabled": True,
        "category": "PERIMETER"
    },
    {
        "id": "RULE_BRAND_TYPO_COMBOSQUAT",
        "name": "Combosquatting de Termos Críticos de Negócio",
        "description": "Uso de termos sensíveis como 'login', '2via', 'atendimento', 'recuperacao' anexados ao nome da marca.",
        "severity": "HIGH",
        "confidence": 90,
        "weight": 20,
        "enabled": True,
        "category": "BRAND_PROTECTION"
    },
    {
        "id": "RULE_TRANSACTION_ANOMALY",
        "name": "Concentração Anômala de Pagamentos e Desvio Benford",
        "description": "Inconsistências estatísticas em lotes de faturamento ou desvio no primeiro dígito da Lei de Benford.",
        "severity": "MEDIUM",
        "confidence": 82,
        "weight": 15,
        "enabled": True,
        "category": "FINANCIAL_FRAUD"
    }
]

# ── WATCHLISTS DATASET ────────────────────────────────────────────────────────

WATCHLISTS_DATASET = [
    {
        "id": "WCH-01",
        "name": "Marcas do Ecossistema Corporativo",
        "category": "BRAND",
        "targets": ["Nubank", "Banco Itaú", "Banco Inter", "Mercado Livre", "Magalu"],
        "active_alerts_count": 8,
        "last_scan_utc": _ts(delta_minutes=10)
    },
    {
        "id": "WCH-02",
        "name": "Prefixos de ASNs e Hosting Bulletproof",
        "category": "INFRASTRUCTURE",
        "targets": ["AS49453", "AS200052", "185.220.101.0/24", "194.26.29.0/24"],
        "active_alerts_count": 5,
        "last_scan_utc": _ts(delta_minutes=25)
    },
    {
        "id": "WCH-03",
        "name": "CNPJs Investigados por Fraude Societária",
        "category": "COMPANY",
        "targets": ["36.126.857/0001-49", "38.291.802/0001-14", "37.404.287/0001-09"],
        "active_alerts_count": 4,
        "last_scan_utc": _ts(delta_minutes=40)
    }
]
