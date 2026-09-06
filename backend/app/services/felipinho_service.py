"""
Felipinho AI Service — morfeusec OSINT
Intelligent Cybersecurity & Platform Interpretation Assistant.
Provides domain-specific reasoning for OSINT, Mobile Pentesting (OWASP MASVS),
Vulnerability Management, Security Controls, and Remediation Strategies.
"""
import re
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
import structlog

logger = structlog.get_logger(__name__)


class FelipinhoAIService:
    """
    Felipinho AI Assistant Engine — Specialized in Offensive Security,
    OSINT Perimeter Analysis, Mobile App Pentesting, and Regulatory Compliance.
    """

    KNOWLEDGE_BASE = [
        {
            "keywords": ["masvs", "apk", "mobile", "ios", "ipa", "android", "score masvs", "celular"],
            "title": "Interpretação do Pentest Mobile & OWASP MASVS v2.0",
            "response": """### 📱 Como Interpretar o Pentest Mobile (OWASP MASVS v2.0)

O módulo **Mobile Pentest** do **morfeusec OSINT** audita seu pacote (.APK ou .IPA) em 7 categorias do padrão internacional **OWASP MASVS v2.0**:

1. **MASVS-STORAGE (Armazenamento de Dados)**:
   - Avalia se há dados sensíveis em arquivos compartilhados (`allowBackup="true"`, SharedPreferences sem criptografia).
   - *Risco:* Extração de banco de dados e tokens via `adb backup`.

2. **MASVS-CRYPTO (Criptografia)**:
   - Verifica o uso de cifras inseguras como `AES/ECB` (sem IV) ou funções de hash obsoletas (`MD5`, `SHA-1`).
   - *Recomendação:* Utilizar `AES/GCM/NoPadding` com chaves armazenadas no *Android Keystore* ou *iOS Keychain*.

3. **MASVS-NETWORK (Comunicação Segura)**:
   - Identifica se o app possui **SSL Certificate Pinning** e se bloqueia tráfego HTTP em texto claro (`usesCleartextTraffic="false"`).

4. **MASVS-PLATFORM (Interação com o SO)**:
   - Audita componentes exportados (Activities, BroadcastReceivers, ContentProviders) e permissões críticas como `SYSTEM_ALERT_WINDOW` (vetor de ataques de **Tapjacking**).

5. **MASVS-RESILIENCE (Anti-Engenharia Reversa)**:
   - Avalia se o app detecta **Root / Jailbreak** e instrumentação dinâmica por **Frida/Xposed**.

💡 *Dica do Felipinho:* Você pode exportar o laudo completo em **PDF (Português/Inglês)** e a planilha **Excel (.xlsx)** diretamente na barra superior da aba Mobile Pentest!"""
        },
        {
            "keywords": ["dmarc", "spf", "email", "spoofing", "phishing", "mx", "p=reject", "p=quarantine", "p=none"],
            "title": "Interpretação de E-mail Security & DMARC",
            "response": """### ✉️ Interpretação de Segurança de E-mail & DMARC

No módulo **OSINT Intelligence**, a auditoria de e-mail verifica a blindagem contra falsificação de identidade (*Spoofing*) e *Phishing*:

* **DMARC `p=reject` (Proteção Máxima)**: O servidor de destino rejeita sumariamente qualquer e-mail que tente se passar pelo seu domínio sem assinatura válida SPF/DKIM.
* **DMARC `p=quarantine` (Moderado)**: Os e-mails não autorizados são direcionados para a caixa de spam/lixo eletrônico.
* **DMARC `p=none` (Monitoramento Apenas / Risco)**: O domínio apenas recebe relatórios, **permitindo** que invasores enviem e-mails forjados em nome da sua empresa.
* **SPF (`v=spf1 ...`)**: Define quais IPs/servidores têm permissão explícita para disparar mensagens pelo domínio.

🔒 *Diagnóstico Recomendado:* Configure `v=DMARC1; p=reject; rua=mailto:dmarc@seudominio.com;` para garantir conformidade e proteção contra ataques de Engenharia Social."""
        },
        {
            "keywords": ["reconhecimento", "doh", "dns", "caa", "crt.sh", "subdominios", "transparency", "dorks", "google dork"],
            "title": "Como Funciona o Motor de OSINT & Reconhecimento",
            "response": """### 🌐 Motor de Inteligência OSINT & Reconhecimento Perimetral

O **morfeusec OSINT** executa varreduras passivas e ativas de inteligência sem degradar a aplicação alvo:

1. **DNS-over-HTTPS (DoH)**: Consulta servidores Cloudflare e Google DoH para mapear registros `A`, `AAAA`, `MX`, `TXT`, `NS`, `SOA` e `CAA`.
2. **Registro CAA (Certificate Authority Authorization)**: Impede que Autoridades Certificadoras não autorizadas emitam certificados SSL para seu domínio.
3. **Certificate Transparency (crt.sh)**: Minera logs públicos de emissão de certificados para descobrir subdomínios históricos, servidores de homologação (`stage`, `dev`, `vpn`, `api`) e SANs.
4. **Google Dorking Matrix**: Gera consultas refinadas para encontrar arquivos `.env`, `.git`, backups `.sql` e painéis de autenticação expostos."""
        },
        {
            "keywords": ["waf", "akamai", "cloudflare", "ghost", "borda", "ddos", "akamaighost"],
            "title": "Detecção de WAF (Akamai / Cloudflare / AWS)",
            "response": """### 🛡️ Detecção e Interpretação de WAF de Borda

A detecção de Web Application Firewall analisa cabeçalhos HTTP e comportamento de rede:

* **Akamai Edge WAF (`AkamaiGHost`)**: Identifica a presença do *Akamai Kona Site Defender* ou *App & API Protector*. Protege contra DDoS e injeção de payload na borda.
* **Cloudflare WAF (`cf-ray` / Server: cloudflare)**: Indica proxy reverso com proteção perimetral ativa.
* **AWS CloudFront / WAF (`x-amz-cf-id`)**: Indica distribuição via CDN da Amazon com regras de segurança ativas.
* **Sem WAF Detectado**: A origem está diretamente exposta à internet, aumentando a nota de risco da aplicação perante ataques de força bruta e exploração automatizada."""
        },
        {
            "keywords": ["controles", "security controls", "32", "bacen", "cmn 4.893", "laudo", "cis"],
            "title": "32 Controles de Segurança & Conformidade",
            "response": """### 🛡️ Central de Controles de Segurança (32 Controles)

A aba **Controles de Segurança** executa testes técnicos automatizados baseados no BACEN e CIS Controls:

* **SEC-EXT-01 a 03**: TLS 1.3 / 1.2, Cifras ECDHE seguras, cabeçalhos HSTS, CSP e CORS restritivo.
* **SEC-EXT-04 a 06**: Bloqueio de arquivos sensíveis (`.env`, `.git`), ocultação de banners de servidor e proteção contra força bruta (Rate Limiting).
* **SEC-EXT-07 a 15**: Políticas de cookies seguros (`Secure`, `HttpOnly`, `SameSite`), desativação de métodos HTTP inseguros (`TRACE`, `TRACK`), e integridade DNS.
* **SEC-EXT-16 a 32**: Controles avançados de injeção, cabeçalhos de permissão e sanitização.

📊 *Exportações Disponíveis:*
- **Planilha Excel (.xlsx)**: Trilha de auditoria criptográfica completa.
- **Laudo PDF Formal**: Relatório de conformidade assinado com hashes SHA-256."""
        },
        {
            "keywords": ["autor", "felipe", "costa", "felipe costa", "quem criou", "quem fez", "desenvolvedor", "contato", "email"],
            "title": "Sobre o Autor & Plataforma morfeusec OSINT",
            "response": """### 👨‍💻 Sobre a Criação do morfeusec OSINT

A plataforma **morfeusec OSINT** foi idealizada, arquitetada e escrita por:

* **Autor:** Felipe Costa
* **E-mail de Contato:** [`fsec.costa@gmail.com`](mailto:fsec.costa@gmail.com)
* **Especialidade:** Arquitetura de Segurança Ofensiva, Inteligência de Ameaças (OSINT), Mobile Pentest e Validação Contínua de Controles.

Qualquer dúvida sobre implementações personalizadas, módulos adicionais ou consultoria de segurança, entre em contato diretamente pelo e-mail acima!"""
        },
        {
            "keywords": ["como usar", "ajuda", "duvida", "iniciar", "scanner", "passo a passo"],
            "title": "Guia Rápido de Utilização do morfeusec OSINT",
            "response": """### 🚀 Guia Rápido de Utilização da Plataforma

1. **Dashboard:** Visão consolidada de KPIs, distribuição de vulnerabilidades e postura geral de risco.
2. **Scanner:** Insira uma URL ou lista de URLs para executar varreduras ativas automatizadas com Spider e detecção OWASP Top 10.
3. **Mobile Pentest (APK/iOS):** Arraste e solte arquivos `.apk` ou `.ipa` para descompilar o binário, extrair chaves de API hardcoded e gerar relatórios em PDF (PT/EN) e Excel.
4. **OSINT Intelligence:** Digite um domínio corporativo (ex: `empresa.com.br`) para mapear subdomínios, ASN, WAF, DNS DoH e Google Dorks.
5. **Controles de Segurança:** Audite 32 controles perimétricos com validação contínua e emissão de laudo formal.
6. **Reports:** Visualize e baixe os relatórios consolidados gerados em PDF e Excel."""
        }
    ]

    async def answer_query(self, message: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Processes user query and provides specialized, technical guidance with Felipinho AI persona.
        """
        clean_msg = message.strip().lower()
        now_iso = datetime.now(timezone.utc).isoformat()

        # Match against knowledge base
        best_match = None
        highest_score = 0

        for item in self.KNOWLEDGE_BASE:
            score = 0
            for kw in item["keywords"]:
                if kw in clean_msg:
                    score += len(kw)
            if score > highest_score:
                highest_score = score
                best_match = item

        if best_match and highest_score > 0:
            response_text = best_match["response"]
            topic_title = best_match["title"]
        else:
            # Contextual AI fallback reasoning
            response_text = self._generate_contextual_response(message, clean_msg)
            topic_title = "Orientação Técnica Felipinho AI"

        return {
            "assistant": "Felipinho AI",
            "author_attribution": "Escrito por Felipe Costa - fsec.costa@gmail.com",
            "title": topic_title,
            "response": response_text,
            "timestamp": now_iso,
            "suggested_actions": [
                "Como auditar um aplicativo Android APK?",
                "O que significa DMARC p=reject?",
                "Como interpretar o WAF Akamai na plataforma?",
                "Quais são os 32 controles de segurança?",
            ]
        }

    def _generate_contextual_response(self, raw_message: str, clean_msg: str) -> str:
        """Generates dynamic cyber guidance when no direct keyword is found."""
        return f"""### 🤖 Resposta do Felipinho AI

Olá! Analisei sua dúvida: **"{raw_message}"**.

Na plataforma **morfeusec OSINT**, todas as análises seguem os mais altos padrões de auditoria (*OWASP MASVS*, *OWASP Top 10*, *NIST SP 800-115* e *CIS Controls*).

Aqui estão algumas áreas principais onde posso te ajudar:
1. **📱 Mobile Pentest:** Interpretação de vulnerabilidades em APKs/IPAs, descompilação de Manifest, chaves hardcoded e pontuações OWASP MASVS.
2. **🌐 OSINT & Recon:** Como analisar zonas DNS (DoH), registros CAA, Certificate Transparency (`crt.sh`), identificação de WAF Akamai e detecção de S3 buckets.
3. **✉️ Anti-Spoofing:** Avaliação e recomendações de políticas SPF e DMARC.
4. **🛡️ Controles de Segurança:** Diagnóstico e relatórios dos 32 controles técnicos.
5. **📄 Relatórios & Exportações:** Como extrair relatórios em PDF (Português/Inglês) e planilhas Excel (.xlsx).

💡 *Você pode clicar em uma das sugestões rápidas abaixo ou digitar uma pergunta específica sobre qualquer tela da plataforma!*"""


felipinho_service = FelipinhoAIService()
