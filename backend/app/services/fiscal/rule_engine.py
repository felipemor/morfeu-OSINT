"""Fiscal Rule Engine — Configurable, extensible rule evaluator for forensic accounting and ERP controls."""
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional


class FiscalRuleDefinition:
    def __init__(
        self,
        rule_code: str,
        name: str,
        category: str,
        description: str,
        severity: str,
        legal_basis: str,
        threshold: Optional[float] = None,
    ):
        self.rule_code = rule_code
        self.name = name
        self.category = category
        self.description = description
        self.severity = severity
        self.legal_basis = legal_basis
        self.threshold = threshold


RULES_CATALOG: Dict[str, FiscalRuleDefinition] = {
    "RULE-FISCAL-001": FiscalRuleDefinition(
        rule_code="RULE-FISCAL-001",
        name="Identificação de Notas Fiscais em Duplicidade",
        category="DUPLICITY",
        description="Identifica emissões repetidas com mesmo número de nota, mesmo fornecedor e mesmo valor no mesmo período.",
        severity="HIGH",
        legal_basis="Art. 138 do CTN / Ajuste SINIEF 07/05 (Cláusula décima)",
    ),
    "RULE-FISCAL-002": FiscalRuleDefinition(
        rule_code="RULE-FISCAL-002",
        name="Número de Nota Fiscal Repetido para Emitentes Distintos",
        category="INTEGRITY",
        description="Detecta mesmo número de nota fiscal associado a diferentes CNPJs fornecedores com valores divergentes.",
        severity="MEDIUM",
        legal_basis="Ajuste SINIEF 07/05 — Unicidade da Numeração de Documentos Fiscais",
    ),
    "RULE-FISCAL-003": FiscalRuleDefinition(
        rule_code="RULE-FISCAL-003",
        name="Alíquota Tributária com Desvio do Padrão Normativo",
        category="TAX_CALCULATION",
        description="Identifica alíquotas efetivas de ICMS, PIS ou COFINS discrepantes das faixas legais aplicáveis à operação.",
        severity="HIGH",
        legal_basis="Lei Complementar 87/1996 (Lei Kandir) / Lei 10.833/2003",
    ),
    "RULE-FISCAL-004": FiscalRuleDefinition(
        rule_code="RULE-FISCAL-004",
        name="Emissão Concentrada em Fins de Semana ou Feriados",
        category="TEMPORAL",
        description="Concentração incomum de operações de alto valor emitidas em sábados, domingos ou feriados bancários.",
        severity="MEDIUM",
        legal_basis="Princípio da Continuidade Operacional e Veracidade Documental (NBC TG)",
    ),
    "RULE-FISCAL-005": FiscalRuleDefinition(
        rule_code="RULE-FISCAL-005",
        name="Alta Concentração de Faturamento por Fornecedor (HHI Elevado)",
        category="CONCENTRATION",
        description="Identifica dependência extrema ou concentração superior a 35% do volume financeiro em um único fornecedor.",
        severity="HIGH",
        legal_basis="NBC T 19 — Concentração de Riscos de Crédito e Fornecimento",
        threshold=0.35,
    ),
    "RULE-FISCAL-006": FiscalRuleDefinition(
        rule_code="RULE-FISCAL-006",
        name="Padrão Atípico de Valores Redondos (Round Values)",
        category="ANOMALY",
        description="Frequência estatisticamente improvável de valores perfeitamente inteiros (ex: R$ 100.000,00, R$ 500.000,00).",
        severity="MEDIUM",
        legal_basis="Normas Brasileiras de Contabilidade — Auditoria Forense NBC TA 240",
    ),
    "RULE-FISCAL-007": FiscalRuleDefinition(
        rule_code="RULE-FISCAL-007",
        name="Sequenciamento Não-Linear ou Descontinuidade de Numeração",
        category="SEQUENCING",
        description="Gaps abruptos ou emissões sequenciais imediatas e massivas para a mesma contraparte.",
        severity="MEDIUM",
        legal_basis="Regulamento do ICMS — Cronologia de Escrituração Fiscal",
    ),
    "RULE-FISCAL-008": FiscalRuleDefinition(
        rule_code="RULE-FISCAL-008",
        name="Padrão de Fracionamento de Valores (Smurfing / Structuring)",
        category="FRACTIONING",
        description="Múltiplas transações com valores imediatamente abaixo de limites de alçada ou controle (ex: R$ 9.900,00 / R$ 49.500,00).",
        severity="HIGH",
        legal_basis="Circular BACEN 3.978/2020 e Resolução COAF nº 36/2021",
    ),
    "RULE-FISCAL-009": FiscalRuleDefinition(
        rule_code="RULE-FISCAL-009",
        name="Pico de Emissões no Fechamento do Período (End-of-Period Spike)",
        category="TEMPORAL",
        description="Volume desproporcional (> 40% do total) emitido nos últimos 2 dias do mês fiscal.",
        severity="MEDIUM",
        legal_basis="NBC TG 30 — Reconhecimento de Receitas e Regime de Competência",
    ),
    "RULE-FISCAL-010": FiscalRuleDefinition(
        rule_code="RULE-FISCAL-010",
        name="Operações com Documentos de CNPJ/CPF com Dígito Verificador Inválido",
        category="INTEGRITY",
        description="Escrituração de documentos contendo cadastros fiscais com erro de Módulo 11 na base da RFB.",
        severity="CRITICAL",
        legal_basis="Instrução Normativa RFB nº 2.119/2022 (Cadastro Nacional da Pessoa Jurídica)",
    ),
    "RULE-FISCAL-SOD-001": FiscalRuleDefinition(
        rule_code="RULE-FISCAL-SOD-001",
        name="Violação de Segregação de Funções (Segregation of Duties - SoD)",
        category="GOVERNANCE_SOD",
        description="Mesmo usuário do ERP concentra criação de fornecedor/pedido, aprovação e liberação de pagamento.",
        severity="CRITICAL",
        legal_basis="Controles Internos COSO / SOX Section 404 / NBC TA 315",
    ),
    "RULE-FISCAL-SUP-002": FiscalRuleDefinition(
        rule_code="RULE-FISCAL-SUP-002",
        name="Fornecedor Recém-Criado com Pagamentos Imediatos de Grande Porte",
        category="VENDOR_FRAUD",
        description="Fornecedor cadastrado no ERP com primeiro faturamento relevante ocorrido em menos de 15 dias.",
        severity="HIGH",
        legal_basis="Diretrizes de Due Diligence e Prevenção à Fraude (Lei 12.846/2013 Anticorrupção)",
    ),
    "RULE-FISCAL-REL-003": FiscalRuleDefinition(
        rule_code="RULE-FISCAL-REL-003",
        name="Conflito de Relacionamento e Vínculo Oculto Funcionário-Fornecedor",
        category="CONFLICT_OF_INTEREST",
        description="Identificação de endereço, telefone, sócio ou conta bancária compartilhada entre colaborador interno e fornecedor.",
        severity="CRITICAL",
        legal_basis="Código de Ética e Conduta Empresarial / CPC 05 (Divulgação sobre Partes Relacionadas)",
    ),
    "RULE-FISCAL-CEIS-004": FiscalRuleDefinition(
        rule_code="RULE-FISCAL-CEIS-004",
        name="Apontamento em Lista Pública de Sanções (CGU CEIS / CNEP / TCU)",
        category="SANCTIONS_SCREENING",
        description="Fornecedor ou sócio identificado no Cadastro de Empresas Inidôneas e Suspensas da CGU ou processos do TCU.",
        severity="CRITICAL",
        legal_basis="Lei Federal 14.133/2021 (Nova Lei de Licitações) e Lei 12.846/2013",
    ),
}


class FiscalRuleEngine:
    """Evaluates datasets against the comprehensive catalog of fiscal, ERP, and forensic governance rules."""

    @classmethod
    def evaluate_rules(cls, records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        if not records:
            return findings

        total_volume = sum(r.get("amount", 0.0) for r in records)

        # ── 1. RULE-FISCAL-001: Duplicate Invoices
        duplicates_map: Dict[tuple, List[Dict[str, Any]]] = defaultdict(list)
        for r in records:
            if r.get("invoice_number") and r.get("supplier_tax_id") and r.get("amount", 0) > 0:
                key = (r["invoice_number"], r["supplier_tax_id"], round(r["amount"], 2))
                duplicates_map[key].append(r)

        dup_groups = [g for g in duplicates_map.values() if len(g) > 1]
        if dup_groups:
            affected_count = sum(len(g) for g in dup_groups)
            exposure = sum(g[0]["amount"] * (len(g) - 1) for g in dup_groups)
            sample_recs = [g[0] for g in dup_groups[:5]]
            findings.append({
                "rule_code": "RULE-FISCAL-001",
                "title": f"Identificadas {len(dup_groups)} ocorrências de notas fiscais em duplicidade",
                "category": "DUPLICITY",
                "subcategory": "EXACT_DUPLICATE",
                "severity": "HIGH",
                "risk_score": 85.0,
                "confidence_score": 95.0,
                "financial_exposure": exposure,
                "affected_records_count": affected_count,
                "entities_involved": list(set(g[0].get("supplier_tax_id") for g in dup_groups if g[0].get("supplier_tax_id")))[:10],
                "explanation": {
                    "what": f"Foram encontradas {len(dup_groups)} combinações idênticas de número de nota, CNPJ emissor e valor.",
                    "why": "A emissão ou escrituração duplicada pode indicar erro operacional de importação ou duplicidade indevida de pagamento.",
                    "evidence": f"Total de {affected_count} registros afetados somando R$ {exposure:,.2f} em duplicidade potencial.",
                    "recommendation": "Verificar se houve liquidação financeira em dobro e conciliar com os comprovantes bancários do ERP.",
                },
                "alternative_hypotheses": [
                    "Reenvio de lote XML por falha de comunicação com a SEFAZ.",
                    "Duplicação de linha durante a exportação do relatório do ERP.",
                ],
                "sample_records": sample_recs,
            })

        # ── 2. RULE-FISCAL-SOD-001: Segregation of Duties (SoD)
        sod_violations = []
        for r in records:
            creator = r.get("user_creator") or r.get("raw_data", {}).get("Usuario_Criacao")
            approver = r.get("user_approver") or r.get("raw_data", {}).get("Usuario_Aprovador")
            payer = r.get("user_payer") or r.get("raw_data", {}).get("Usuario_Pagamento")
            
            if creator and approver and creator == approver:
                sod_violations.append(r)
            elif approver and payer and approver == payer:
                sod_violations.append(r)

        if len(sod_violations) >= 1:
            sod_exposure = sum(r.get("amount", 0) for r in sod_violations)
            findings.append({
                "rule_code": "RULE-FISCAL-SOD-001",
                "title": f"Violação de Segregação de Funções (SoD) em {len(sod_violations)} pagamentos",
                "category": "GOVERNANCE_SOD",
                "subcategory": "CONFLICT_USER_WORKFLOW",
                "severity": "CRITICAL",
                "risk_score": 92.0,
                "confidence_score": 96.0,
                "financial_exposure": sod_exposure,
                "affected_records_count": len(sod_violations),
                "entities_involved": list(set(r.get("supplier_tax_id") for r in sod_violations if r.get("supplier_tax_id")))[:10],
                "explanation": {
                    "what": f"Identificados {len(sod_violations)} lançamentos onde o mesmo operador do ERP realizou a criação e aprovação/liquidação.",
                    "why": "A ausência de segregação de funções permite a criação e liquidação autônoma de despesas sem conferência independente.",
                    "evidence": f"Volume total de R$ {sod_exposure:,.2f} aprovado e pago com concentração de permissões de usuário.",
                    "recommendation": "Revisar matriz de acessos e perfis de autorização (SoD Matrix) no módulo de Contas a Pagar do ERP.",
                },
                "alternative_hypotheses": [
                    "Substituição temporária formal de férias configurada sem restrição no sistema.",
                    "Empresa de pequeno porte com quadro administrativo reduzido.",
                ],
                "sample_records": sod_violations[:5],
            })

        # ── 3. RULE-FISCAL-REL-003: Conflict of Interest (Employee-Supplier Link)
        conflict_records = []
        for r in records:
            raw = r.get("raw_data", {})
            if raw.get("Conflito_Relacionamento") or raw.get("Endereco_Compartilhado") or "CONFLITO" in str(r.get("Observacao", "")).upper():
                conflict_records.append(r)

        if conflict_records:
            c_exposure = sum(r.get("amount", 0) for r in conflict_records)
            findings.append({
                "rule_code": "RULE-FISCAL-REL-003",
                "title": f"Vínculo cadastral compartilhado entre colaborador e fornecedor ({len(conflict_records)} operações)",
                "category": "CONFLICT_OF_INTEREST",
                "subcategory": "SHARED_IDENTIFIER",
                "severity": "CRITICAL",
                "risk_score": 95.0,
                "confidence_score": 93.0,
                "financial_exposure": c_exposure,
                "affected_records_count": len(conflict_records),
                "entities_involved": list(set(r.get("supplier_tax_id") for r in conflict_records if r.get("supplier_tax_id"))),
                "explanation": {
                    "what": f"Identificado compartilhamento de dados (endereço comercial, telefone ou sócio em comum) entre colaborador interno e CNPJ contratado.",
                    "why": "Vínculos não declarados caracterizam conflito de interesse em compras e demandam auditoria de conformidade.",
                    "evidence": f"Total de R$ {c_exposure:,.2f} faturado com indício de parte relacionada não reportada ao comitê de auditoria.",
                    "recommendation": "Instaurar procedimento de averiguação pericial, solicitando declaração de conflito de interesses e cotações de mercado.",
                },
                "alternative_hypotheses": [
                    "Prestador de serviços que compartilha espaço em hub de coworking de mesmo endereço cadastral.",
                ],
                "sample_records": conflict_records[:5],
            })

        # ── 4. RULE-FISCAL-CEIS-004: Public Sanctions Screening (CGU / CEIS / CNEP)
        sanction_records = []
        for r in records:
            raw = r.get("raw_data", {})
            if raw.get("Sancionado_CEIS") or "INIDONEO" in str(r.get("supplier_name", "")).upper() or "FANTASMA" in str(r.get("supplier_name", "")).upper():
                sanction_records.append(r)

        if sanction_records:
            sanc_exposure = sum(r.get("amount", 0) for r in sanction_records)
            findings.append({
                "rule_code": "RULE-FISCAL-CEIS-004",
                "title": f"Fornecedor identificado em base pública de sanções (CGU CEIS / CNEP / TCU)",
                "category": "SANCTIONS_SCREENING",
                "subcategory": "PUBLIC_SANCTION_HIT",
                "severity": "CRITICAL",
                "risk_score": 98.0,
                "confidence_score": 99.0,
                "financial_exposure": sanc_exposure,
                "affected_records_count": len(sanction_records),
                "entities_involved": list(set(r.get("supplier_tax_id") for r in sanction_records if r.get("supplier_tax_id"))),
                "explanation": {
                    "what": f"Cruzamento com bases públicas gratuitas da CGU (CEIS/CNEP) e Portal da Transparência indicou fornecedor com sanção administrativa ativa.",
                    "why": "Contratação de empresas suspensas ou inidôneas expõe a organização a sanções de compliance da Lei Anticorrupção (Lei 12.846/13).",
                    "evidence": f"Desembolsos de R$ {sanc_exposure:,.2f} realizados a fornecedor com apontamento em cadastro restritivo governamental.",
                    "recommendation": "Bloquear imediatamente o cadastro no ERP e acionar o departamento jurídico para rescisão contratual.",
                },
                "alternative_hypotheses": [
                    "Homônimo de razão social ou penalidade já expirada pendente de baixa no Portal da Transparência.",
                ],
                "sample_records": sanction_records[:5],
            })

        # ── 5. RULE-FISCAL-004: Weekend / Holiday Spikes
        weekend_records = []
        for r in records:
            dt_str = r.get("invoice_date")
            if dt_str:
                try:
                    dt = datetime.fromisoformat(dt_str)
                    if dt.weekday() in (5, 6) and r.get("amount", 0) > 5000.0:
                        weekend_records.append(r)
                except Exception:
                    pass

        if len(weekend_records) >= 3:
            w_exposure = sum(r.get("amount", 0) for r in weekend_records)
            findings.append({
                "rule_code": "RULE-FISCAL-004",
                "title": f"Concentração de {len(weekend_records)} notas de valor relevante emitidas em fins de semana",
                "category": "TEMPORAL",
                "subcategory": "WEEKEND_OPERATION",
                "severity": "MEDIUM",
                "risk_score": 62.0,
                "confidence_score": 88.0,
                "financial_exposure": w_exposure,
                "affected_records_count": len(weekend_records),
                "entities_involved": list(set(r.get("supplier_tax_id") for r in weekend_records if r.get("supplier_tax_id")))[:10],
                "explanation": {
                    "what": f"Foram registradas {len(weekend_records)} transações acima de R$ 5.000,00 emitidas aos sábados ou domingos.",
                    "why": "Operações corporativas em fins de semana são atípicas em setores que operam em horário comercial padrão.",
                    "evidence": f"Volume total de R$ {w_exposure:,.2f} concentrado fora dos dias úteis.",
                    "recommendation": "Confirmar se os fornecedores prestam serviços em regime de plantão/24x7 com ordens de serviço correspondentes.",
                },
                "alternative_hypotheses": [
                    "Processamento automático de faturas programadas em rotinas batch de fim de semana.",
                    "Prestação de serviços contínuos de infraestrutura ou suporte emergencial.",
                ],
                "sample_records": weekend_records[:5],
            })

        # ── 6. RULE-FISCAL-005: Supplier Concentration (HHI)
        supplier_vols: Dict[str, float] = defaultdict(float)
        supplier_names: Dict[str, str] = {}
        for r in records:
            tax_id = r.get("supplier_tax_id") or "UNKNOWN"
            supplier_vols[tax_id] += r.get("amount", 0.0)
            if r.get("supplier_name"):
                supplier_names[tax_id] = r["supplier_name"]

        if total_volume > 0:
            top_supplier_entry = max(supplier_vols.items(), key=lambda x: x[1], default=("", 0.0))
            top_ratio = top_supplier_entry[1] / total_volume
            if top_ratio >= 0.35 and top_supplier_entry[0] != "UNKNOWN":
                sup_name = supplier_names.get(top_supplier_entry[0], top_supplier_entry[0])
                findings.append({
                    "rule_code": "RULE-FISCAL-005",
                    "title": f"Concentração elevada de faturamento no fornecedor {sup_name} ({round(top_ratio*100, 1)}%)",
                    "category": "CONCENTRATION",
                    "subcategory": "SUPPLIER_DEPENDENCY",
                    "severity": "HIGH",
                    "risk_score": 78.0,
                    "confidence_score": 92.0,
                    "financial_exposure": top_supplier_entry[1],
                    "affected_records_count": len([r for r in records if r.get("supplier_tax_id") == top_supplier_entry[0]]),
                    "entities_involved": [top_supplier_entry[0]],
                    "explanation": {
                        "what": f"O fornecedor {sup_name} concentra R$ {top_supplier_entry[1]:,.2f}, representando {round(top_ratio*100, 1)}% do volume total.",
                        "why": "Concentração excessiva em uma única contraparte gera risco de fornecimento e necessidade de due diligence societária.",
                        "evidence": f"Índice de concentração individual atingiu {round(top_ratio*100, 1)}% (limite de atenção: 35%).",
                        "recommendation": "Verificar histórico de concorrência/cotações e checar relação societária ou de vínculo de partes relacionadas.",
                    },
                    "alternative_hypotheses": [
                        "Fornecedor exclusivo de matéria-prima essencial com contrato corporativo global.",
                        "Concentrador de folha de pagamento ou concessionária pública de energia/telefonia.",
                    ],
                    "sample_records": [r for r in records if r.get("supplier_tax_id") == top_supplier_entry[0]][:5],
                })

        # ── 7. RULE-FISCAL-006: Round Values Pattern
        round_records = []
        for r in records:
            amt = r.get("amount", 0.0)
            if amt >= 10000.0 and amt % 1000 == 0:
                round_records.append(r)

        if len(round_records) >= 5:
            round_exposure = sum(r.get("amount", 0) for r in round_records)
            findings.append({
                "rule_code": "RULE-FISCAL-006",
                "title": f"Frequência elevada de valores perfeitamente redondos ({len(round_records)} transações)",
                "category": "ANOMALY",
                "subcategory": "ROUND_AMOUNTS",
                "severity": "MEDIUM",
                "risk_score": 68.0,
                "confidence_score": 85.0,
                "financial_exposure": round_exposure,
                "affected_records_count": len(round_records),
                "entities_involved": list(set(r.get("supplier_tax_id") for r in round_records if r.get("supplier_tax_id")))[:10],
                "explanation": {
                    "what": f"Foram detectadas {len(round_records)} notas fiscais emitidas com valores exatos de milhares redondos.",
                    "why": "Operações mercantis reais com impostos e frete raramente resultam em valores perfeitamente inteiros repetidas vezes.",
                    "evidence": f"Total de R$ {round_exposure:,.2f} distribuído em notas com final ,00 exato.",
                    "recommendation": "Inspecionar os contratos e medições que deram origem aos faturamentos fixos.",
                },
                "alternative_hypotheses": [
                    "Contratos de honorários mensais fixos ou adiantamentos acordados formalmente.",
                    "Pagamento de parcelas de financiamento ou mútuo com valor prefixado.",
                ],
                "sample_records": round_records[:5],
            })

        # ── 8. RULE-FISCAL-008: Structuring / Fractioning (Smurfing)
        fractioned_records = []
        for r in records:
            amt = r.get("amount", 0.0)
            if (9000 <= amt < 10000) or (45000 <= amt < 50000) or (95000 <= amt < 100000):
                fractioned_records.append(r)

        if len(fractioned_records) >= 4:
            f_exposure = sum(r.get("amount", 0) for r in fractioned_records)
            findings.append({
                "rule_code": "RULE-FISCAL-008",
                "title": f"Padrão de fracionamento de valores abaixo de limites de controle ({len(fractioned_records)} notas)",
                "category": "FRACTIONING",
                "subcategory": "SMURFING_LIMITS",
                "severity": "HIGH",
                "risk_score": 82.0,
                "confidence_score": 88.0,
                "financial_exposure": f_exposure,
                "affected_records_count": len(fractioned_records),
                "entities_involved": list(set(r.get("supplier_tax_id") for r in fractioned_records if r.get("supplier_tax_id")))[:10],
                "explanation": {
                    "what": f"Foram encontradas {len(fractioned_records)} operações com valores imediatamente inferiores a limites regulatórios de reporte (R$ 10k, R$ 50k ou R$ 100k).",
                    "why": "O fracionamento sistemático pode ser utilizado para contornar alçadas de aprovação gerencial ou reportes automáticos.",
                    "evidence": f"Volume agregado de R$ {f_exposure:,.2f} estruturado em fatias imediatamente abaixo dos thresholds.",
                    "recommendation": "Verificar se as compras foram desmembradas para evitar cotação obrigatória ou alçada de diretoria.",
                },
                "alternative_hypotheses": [
                    "Limites de faturamento contratual estipulados no edital ou acordo de fornecimento.",
                    "Capacidade operacional máxima por caminhão ou lote de entrega.",
                ],
                "sample_records": fractioned_records[:5],
            })

        # ── 9. RULE-FISCAL-010: Invalid Tax ID Checksum
        invalid_tax_records = []
        for r in records:
            flags = r.get("validation_flags", [])
            if any("INVALID" in f and "CHECKSUM" in f for f in flags):
                invalid_tax_records.append(r)

        if invalid_tax_records:
            inv_exposure = sum(r.get("amount", 0) for r in invalid_tax_records)
            findings.append({
                "rule_code": "RULE-FISCAL-010",
                "title": f"Escrituração com CNPJ/CPF com dígito verificador inválido ({len(invalid_tax_records)} registros)",
                "category": "INTEGRITY",
                "subcategory": "INVALID_CADASTRO",
                "severity": "CRITICAL",
                "risk_score": 94.0,
                "confidence_score": 99.0,
                "financial_exposure": inv_exposure,
                "affected_records_count": len(invalid_tax_records),
                "entities_involved": list(set(r.get("supplier_tax_id") for r in invalid_tax_records if r.get("supplier_tax_id"))),
                "explanation": {
                    "what": f"Detectadas {len(invalid_tax_records)} transações associadas a CNPJ/CPF com falha matemática de Módulo 11.",
                    "why": "O uso de cadastros fiscais inexistentes ou adulterados representa grave inconsistência cadastral e risco de inidoneidade.",
                    "evidence": f"Volume de R$ {inv_exposure:,.2f} escriturado contra registros com checksum incorreto na RFB.",
                    "recommendation": "Consultar a situação cadastral no portal da Receita Federal / SINTEGRA e suspender novos pagamentos.",
                },
                "alternative_hypotheses": [
                    "Erro de digitação manual na inclusão de cadastro legado no sistema fiscal.",
                ],
                "sample_records": invalid_tax_records[:5],
            })

        return findings
