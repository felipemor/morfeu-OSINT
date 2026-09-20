"""Synthetic Fiscal Data Generator — Generates realistic enterprise test datasets with embedded forensic patterns."""
import random
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Tuple

SYNTHETIC_SUPPLIERS = [
    ("11222333000181", "DISTRIBUIDORA NACIONAL DE ALIMENTOS LTDA", "COMERCIO"),
    ("44555666000192", "LOGISTICA E TRANSPORTES EXPRESSO S.A.", "SERVICOS"),
    ("77888999000103", "TECNO SERVICE CONSULTORIA EM TI LTDA", "TECNOLOGIA"),
    ("12345678000195", "ENGENHARIA E CONSTRUCOES CIVIS LTDA", "OBRAS"),
    ("98765432000110", "SOLUCOES GRAFICAS E EMBALAGENS S/A", "GRAFICA"),
    ("33444555000122", "SEGURANCA PATRIMONIAL E VIGILANCIA LTDA", "SEGURANCA"),
    ("55666777000133", "CONSULTORIA CONTABIL E JURIDICA LTDA", "CONSULTORIA"),
    ("77888111000144", "COMERCIAL DE MATERIAIS ELETRICOS LTDA", "MATERIAIS"),
    ("99111222000155", "PETROLEO E DERIVADOS DO BRASIL S.A.", "COMBUSTIVEL"),
    ("00111222000166", "MANUTENCAO E REPAROS INDUSTRIAIS LTDA", "MANUTENCAO"),
]

INVALID_CNPJS = [
    ("11111111000100", "FORNECEDOR INIDONEO FANTASMA LTDA"),  # Invalid check digit
    ("99999999000199", "CONSULTORIA EIRELI - CADASTRO INATIVO"),  # Invalid check digit
]

ERP_OPERATORS = ["usr_silva", "usr_santos", "usr_costa", "usr_almeida", "usr_pereira"]


class SyntheticFiscalDataGenerator:
    """Generates synthetic fiscal records with deliberate anomalies for demonstration and benchmarking."""

    @classmethod
    def generate_dataset(cls, count: int = 1000) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        """Generates a list of raw dictionaries with realistic fiscal fields."""
        records: List[Dict[str, Any]] = []
        base_date = datetime.now(timezone.utc) - timedelta(days=365)

        for i in range(count):
            day_offset = random.randint(0, 360)
            rec_date = base_date + timedelta(days=day_offset, hours=random.randint(8, 18), minutes=random.randint(0, 59))
            
            # Normal distribution of amounts
            amount = round(random.expovariate(1 / 12500) + 150.0, 2)
            sup_tax_id, sup_name, category = random.choice(SYNTHETIC_SUPPLIERS)
            doc_num = f"NF-{random.randint(100000, 999999)}"

            # ERP Operator flow (normally separated)
            creator = random.choice(ERP_OPERATORS)
            approver = random.choice([u for u in ERP_OPERATORS if u != creator])
            payer = "sys_bank_gateway"

            obs = "[SYNTHETIC DATA — NORMAL]"

            # 1. Deliberate Supplier Concentration: 38% of spend in supplier 0
            if random.random() < 0.38:
                sup_tax_id, sup_name, category = SYNTHETIC_SUPPLIERS[0]
                amount = round(random.uniform(25000.0, 180000.0), 2)

            # 2. Deliberate SoD Violation (Same creator and approver)
            if random.random() < 0.03:
                creator = "usr_silva"
                approver = "usr_silva"
                obs = "[SYNTHETIC DATA — VIOLACAO SoD (MESMO CRIADOR/APROVADOR)]"

            # 3. Deliberate Conflict of Interest (Shared Address/Partner with Employee)
            if random.random() < 0.025:
                sup_tax_id = "88999000000177"
                sup_name = "CONSTRUTORA & REFORMAS ALMEIDA ME"
                obs = "[SYNTHETIC DATA — CONFLITO DE RELACIONAMENTO (ENDERECO COMPARTILHADO)]"

            # 4. Deliberate CEIS / CNEP Sanction Hit
            if random.random() < 0.015:
                sup_tax_id = "77111222000188"
                sup_name = "SERVICOS TERCEIRIZADOS INIDONEO S.A."
                obs = "[SYNTHETIC DATA — SANCIONADO CGU CEIS/CNEP]"

            # 5. Deliberate Round Values
            if random.random() < 0.04:
                amount = float(random.choice([50000, 100000, 150000, 250000, 500000]))

            # 6. Deliberate Smurfing / Fractioning (just below R$ 10k or R$ 50k)
            if random.random() < 0.035:
                amount = round(random.choice([9850.0, 9900.0, 9950.0, 49200.0, 49800.0, 49950.0]), 2)

            # 7. Deliberate Weekend / Sunday operations
            if random.random() < 0.025:
                days_ahead = (5 - rec_date.weekday()) % 7
                rec_date = rec_date + timedelta(days=days_ahead)
                amount = round(random.uniform(15000.0, 85000.0), 2)

            # 8. Deliberate Invalid Checksums (RFB Inconsistencies)
            if random.random() < 0.01:
                sup_tax_id, sup_name = random.choice(INVALID_CNPJS)

            tax_icms = round(amount * 0.18, 2)
            tax_ipi = round(amount * 0.05, 2) if category == "MATERIAIS" else 0.0
            tax_pis = round(amount * 0.0165, 2)
            tax_cofins = round(amount * 0.076, 2)

            records.append({
                "Numero_NF": doc_num,
                "Data_Emissao": rec_date.strftime("%d/%m/%Y"),
                "CNPJ_Fornecedor": sup_tax_id,
                "Razao_Social_Fornecedor": sup_name,
                "CNPJ_Cliente": "00394460000141",
                "Nome_Cliente": "EMPRESA AUDITADA MATRIZ S.A. [DADOS SINTETICOS]",
                "Vl_Total_Nota": amount,
                "Valor_ICMS": tax_icms,
                "Valor_IPI": tax_ipi,
                "Valor_PIS": tax_pis,
                "Valor_COFINS": tax_cofins,
                "CFOP": "5102" if category == "COMERCIO" else "5933",
                "Usuario_Criacao": creator,
                "Usuario_Aprovador": approver,
                "Usuario_Pagamento": payer,
                "Pedido_Compra": f"PO-{random.randint(10000, 99999)}",
                "Observacao": obs,
            })

        # 9. Deliberate Duplicate Invoices injection (5 pairs)
        for d in range(min(5, len(records) // 20)):
            original = records[d * 10]
            dup = dict(original)
            dup["Observacao"] = "[SYNTHETIC DATA — DUPLICIDADE INJETADA]"
            records.append(dup)

        metadata = {
            "dataset_name": f"Auditoria_Fiscal_ERP_SAP_{count}_registros.xlsx",
            "total_records": len(records),
            "is_synthetic": True,
            "synthetic_disclaimer": "ATENÇÃO: Dataset sintético gerado com propósitos exclusivos de teste e benchmarking pericial.",
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

        return records, metadata
