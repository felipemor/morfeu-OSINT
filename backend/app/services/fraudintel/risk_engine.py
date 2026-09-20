"""
FRAUDINTEL — Risk Engine
Explainable 0-100 scoring with transparent factor breakdown.
"""

from typing import List, Dict, Any

class RiskEngine:
    @staticmethod
    def calculate_risk(
        domain_similarity: float = 0.0,
        domain_age_days: int = 365,
        is_bulletproof_host: bool = False,
        has_login_form: bool = False,
        has_beneficiary_mismatch: bool = False,
        has_duplicate_boleto: bool = False,
        correlated_cases_count: int = 0,
        is_known_malicious_ip: bool = False,
        is_homoglyph: bool = False
    ) -> Dict[str, Any]:
        """
        Calculates an explainable 0-100 risk score based on verifiable factors.
        """
        factors = []
        score = 0

        # 1. Brand Similarity
        if domain_similarity >= 0.90:
            pts = 25
            score += pts
            factors.append({
                "factor": f"Extrema Similaridade com Marca ({int(domain_similarity*100)}%)",
                "points": pts,
                "category": "BRAND",
                "description": "Domínio apresenta estrutura ortográfica quase idêntica à marca oficial."
            })
        elif domain_similarity >= 0.70:
            pts = 15
            score += pts
            factors.append({
                "factor": f"Alta Similaridade com Marca ({int(domain_similarity*100)}%)",
                "points": pts,
                "category": "BRAND",
                "description": "Domínio utiliza termos e fonética similares à marca corporativa."
            })

        # 2. Homoglyph Attack
        if is_homoglyph:
            pts = 20
            score += pts
            factors.append({
                "factor": "Uso de Homóglifos Unicode (IDN Spoofing)",
                "points": pts,
                "category": "HOMOGLYPH",
                "description": "Presença de caracteres cirílicos ou acentuados para mascarar o nome visual."
            })

        # 3. Domain Age
        if domain_age_days <= 14:
            pts = 20
            score += pts
            factors.append({
                "factor": f"Domínio Recém-Criado ({domain_age_days} dias)",
                "points": pts,
                "category": "DOMAIN_AGE",
                "description": "Domínios criados há menos de 14 dias possuem probabilidade desproporcional de fraude."
            })
        elif domain_age_days <= 60:
            pts = 10
            score += pts
            factors.append({
                "factor": f"Domínio Jovem ({domain_age_days} dias)",
                "points": pts,
                "category": "DOMAIN_AGE",
                "description": "Tempo de registro inferior a 60 dias."
            })

        # 4. Infrastructure & Hosting
        if is_bulletproof_host or is_known_malicious_ip:
            pts = 20
            score += pts
            factors.append({
                "factor": "Hospedagem em Infraestrutura Suspeita / Fast-Flux",
                "points": pts,
                "category": "INFRASTRUCTURE",
                "description": "Servidor hospedado em ASN com histórico elevado de abrigar phishings e malwares."
            })

        # 5. Phishing / Login Form
        if has_login_form:
            pts = 20
            score += pts
            factors.append({
                "factor": "Página com Formulário de Captura de Credenciais",
                "points": pts,
                "category": "CREDENTIAL_THEFT",
                "description": "Estrutura do formulário simula campos de senha, CPF ou token MFA."
            })

        # 6. Financial / Boleto Divergence
        if has_beneficiary_mismatch:
            pts = 30
            score += pts
            factors.append({
                "factor": "Divergência Grave de Beneficiário no Boleto",
                "points": pts,
                "category": "FINANCIAL",
                "description": "O beneficiário da linha digitável diverge totalmente do emissor contratual."
            })

        if has_duplicate_boleto:
            pts = 15
            score += pts
            factors.append({
                "factor": "Duplicidade de 'Nosso Número' em Linha Digitável",
                "points": pts,
                "category": "FINANCIAL",
                "description": "Detecção de boleto clonado com mesmo identificador em contas distintas."
            })

        # 7. Cross-Case Correlations
        if correlated_cases_count > 0:
            pts = min(15, correlated_cases_count * 8)
            score += pts
            factors.append({
                "factor": f"Correlação com {correlated_cases_count} Incidente(s) Prévio(s)",
                "points": pts,
                "category": "CORRELATION",
                "description": "Entidades como IP, SSL ou CNPJ já foram documentadas em investigações anteriores."
            })

        # Cap score between 0 and 100
        final_score = min(100, max(0, score))

        if final_score >= 80:
            grade = "CRITICAL"
            recommendation = "Acionar Takedown de emergência e bloqueio cautelar imediato."
        elif final_score >= 60:
            grade = "HIGH"
            recommendation = "Investigar com prioridade alta e solicitar congelamento preventivo."
        elif final_score >= 40:
            grade = "MEDIUM"
            recommendation = "Monitorar atividade de rede e solicitar esclarecimentos cadastrais."
        elif final_score >= 20:
            grade = "LOW"
            recommendation = "Manter em observação de baixo risco."
        else:
            grade = "INFORMATIONAL"
            recommendation = "Nenhuma ação imediata necessária."

        confidence = round(min(98.5, 70.0 + (len(factors) * 4.5)), 1)

        return {
            "score": final_score,
            "grade": grade,
            "confidence": confidence,
            "factors": factors,
            "factors_count": len(factors),
            "recommendation": recommendation
        }

risk_engine = RiskEngine()
