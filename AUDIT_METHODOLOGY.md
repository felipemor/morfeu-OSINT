# Metodologia Pericial e Auditoria Analítica — Fiscal Forensic AI

## 1. Princípios da Auditoria Forense Digital

A plataforma **Fiscal Forensic AI** baseia-se em padrões internacionais e nacionais de perícia e auditoria contábil/fiscal, incluindo:

- **NBC TA 240 (R1)** — Responsabilidade do Auditor em Relação a Fraude no Contexto da Auditoria de Demonstrações Contábeis.
- **NBC TP 01 (R1)** — Perícia Contábil e Procedimentos Técnicos Periciais.
- **ISO/IEC 27037** — Diretrizes para Identificação, Coleta, Aquisição e Preservação de Evidência Digital.
- **Ajuste SINIEF 07/05** — Instituição e regras da Nota Fiscal Eletrônica e Documentos Fiscais Digitais.

---

## 2. Postura Não-Acusatória e Classificação de Risco

O sistema adota estritamente a diretriz pericial de **não realizar acusações automáticas**. Em vez de declarações conclusivas, o motor analítico aponta **indícios objetivos, divergências matemáticas e anomalias de conformidade**, classificando-os em:

1. `NORMAL` (Risco < 25)
2. `ATENÇÃO` (Risco 25 – 44)
3. `RISCO MODERADO` (Risco 45 – 69)
4. `ALTO RISCO` (Risco 70 – 84)
5. `RISCO CRÍTICO` (Risco 85 – 100)

Cada apontamento decompõe-se em:
- **WHAT**: O que foi identificado objetivamente nos dados.
- **WHY**: Qual o fundamento regulatório e a lógica do risco.
- **EVIDENCE**: Valores, registros, linhas e hashes criptográficos vinculados.
- **RECOMMENDATION**: Roteiro de procedimentos para verificação in loco pelo auditor humano.
- **ALTERNATIVE HYPOTHESES**: Hipóteses de operação legítima que explicam a divergência.

---

## 3. Formulação Matemática das Regras e Algoritmos

### 3.1 Lei de Benford (Distribuição do Primeiro Dígito)
Para uma série livre de intervenções artificiais, a probabilidade $P(d)$ de um número ter primeiro dígito $d \in \{1, \dots, 9\}$ é:

$$P(d) = \log_{10}\left(1 + \frac{1}{d}\right)$$

O Desvio Médio Absoluto (*Mean Absolute Deviation - MAD*) é calculado por:

$$\text{MAD} = \frac{1}{9} \sum_{d=1}^{9} |O_d - E_d|$$

onde $O_d$ é o percentual observado e $E_d$ é o percentual esperado por Benford.
- $\text{MAD} \le 1.2\%$: Conformidade Estrita
- $1.2\% < \text{MAD} \le 2.2\%$: Conformidade Aceitável
- $2.2\% < \text{MAD} \le 3.0\%$: Não-Conformidade Marginal
- $\text{MAD} > 3.0\%$: Não-Conformidade Substancial (Alerta Forense)

### 3.2 Índice de Concentração Herfindahl-Hirschman (HHI)
Utilizado para medir dependência de fornecedores ou concentração de faturamento:

$$\text{HHI} = \sum_{i=1}^{N} s_i^2$$

onde $s_i$ é o percentual de participação do fornecedor $i$ no volume total ($0 < s_i \le 100$).
- $\text{HHI} < 1500$: Mercado/Desembolso Desconcentrado
- $1500 \le \text{HHI} \le 2500$: Concentração Moderada
- $\text{HHI} > 2500$: Alta Concentração (Risco Operacional e Societário)

### 3.3 Detecção de Outliers por Z-Score e IQR
- **Z-Score**: Identifica transações isoladas acima de 3 desvios padrão: $Z = \frac{x - \mu}{\sigma} > 3.0$
- **Intervalo Interquartil (IQR)**: Faixa de corte superior calculada como $Q3 + 1.5 \times (Q3 - Q1)$.

---

## 4. Cadeia de Custódia e Integridade Digital (SHA-256)

Cada registro de evidência gerado durante a execução da auditoria é selado com um hash criptográfico **SHA-256**:

$$\text{Hash} = \text{SHA256}(\text{DatasetID} \parallel \text{RowNumber} \parallel \text{SnippetJSON} \parallel \text{Timestamp})$$

Garantindo rastreabilidade imutável entre o relatório executivo final e o arquivo original fornecido pelo usuário.
