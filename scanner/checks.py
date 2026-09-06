"""
Security Checks — OWASP Top 10 automated tests (passive + active safe checks)
Similar to OWASP ZAP scanner engine.
"""
import asyncio
import re
from typing import Callable, Awaitable
from urllib.parse import urljoin, urlparse, urlencode, parse_qs, urlencode
import httpx

# ─── Payloads ────────────────────────────────────────────────────────────────

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "'; DROP TABLE users; --",
    "1 AND 1=1",
    "1 AND 1=2",
    "' OR SLEEP(2) --",
    "\" OR \"1\"=\"1",
]

XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "javascript:alert('XSS')",
    "<svg/onload=alert('XSS')>",
    "'><script>alert(1)</script>",
]

SQLI_ERROR_PATTERNS = [
    r"SQL syntax", r"mysql_fetch", r"ORA-\d{5}", r"PostgreSQL.*ERROR",
    r"Warning.*mysql", r"valid MySQL", r"SQLSTATE\[", r"Unclosed quotation",
    r"Microsoft OLE DB", r"ODBC SQL Server", r"SQLite3::", r"syntax error",
    r"mysql_num_rows", r"pg_query\(\)", r"DB2 SQL error",
]

INFO_DISCLOSURE_PATTERNS = [
    (r"(password|passwd|pwd)\s*[:=]\s*\S+", "Password in response"),
    (r"(api[_-]?key|apikey)\s*[:=]\s*\S+", "API Key exposed"),
    (r"stack trace", "Stack trace exposed"),
    (r"Traceback \(most recent", "Python traceback exposed"),
    (r"at .+\(.+\.java:\d+\)", "Java stack trace"),
    (r"Exception in thread", "Java exception exposed"),
    (r"Microsoft\.NET", ".NET framework version exposed"),
    (r"PHP Warning|PHP Fatal error", "PHP error exposed"),
    (r"DEBUG\s*=\s*True", "Debug mode enabled"),
    (r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "UUID/Token in response"),
]

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": "MEDIUM",
        "owasp": "A05:2021 – Security Misconfiguration",
        "desc": "Missing HTTP Strict Transport Security (HSTS) header. Allows downgrade attacks to HTTP.",
        "rec": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
        "cwe": "CWE-319",
    },
    "X-Content-Type-Options": {
        "severity": "LOW",
        "owasp": "A05:2021 – Security Misconfiguration",
        "desc": "Missing X-Content-Type-Options header. Browser may MIME-sniff responses.",
        "rec": "Add: X-Content-Type-Options: nosniff",
        "cwe": "CWE-116",
    },
    "X-Frame-Options": {
        "severity": "MEDIUM",
        "owasp": "A05:2021 – Security Misconfiguration",
        "desc": "Missing X-Frame-Options header. Page may be embedded in iframes (Clickjacking).",
        "rec": "Add: X-Frame-Options: DENY or SAMEORIGIN",
        "cwe": "CWE-1021",
    },
    "Content-Security-Policy": {
        "severity": "MEDIUM",
        "owasp": "A05:2021 – Security Misconfiguration",
        "desc": "Missing Content-Security-Policy header. Increases XSS attack surface.",
        "rec": "Implement a restrictive CSP: Content-Security-Policy: default-src 'self'",
        "cwe": "CWE-693",
    },
    "Referrer-Policy": {
        "severity": "LOW",
        "owasp": "A05:2021 – Security Misconfiguration",
        "desc": "Missing Referrer-Policy header. Referrer information may leak to third parties.",
        "rec": "Add: Referrer-Policy: strict-origin-when-cross-origin",
        "cwe": "CWE-116",
    },
    "Permissions-Policy": {
        "severity": "LOW",
        "owasp": "A05:2021 – Security Misconfiguration",
        "desc": "Missing Permissions-Policy header. Browser features not explicitly restricted.",
        "rec": "Add: Permissions-Policy: camera=(), microphone=(), geolocation=()",
        "cwe": "CWE-16",
    },
}


LogCb = Callable[[str], Awaitable[None]]

# ─── Main scanner class ───────────────────────────────────────────────────────

WAF_SIGNATURES = [
    ("Cloudflare", [("server", r"cloudflare"), ("cf-ray", r".+"), ("cf-cache-status", r".+")]),
    ("AWS WAF / CloudFront", [("x-amzn-requestid", r".+"), ("x-amz-cf-id", r".+"), ("server", r"awselb|amazon|cloudfront")]),
    ("Akamai", [("server", r"akamai"), ("x-akamai-transformed", r".+"), ("x-check-cacheable", r".+")]),
    ("Imperva Incapsula", [("x-iinfo", r".+"), ("x-cdn", r"incapsula"), ("set-cookie", r"incap_ses|visid_incap")]),
    ("ModSecurity / OWASP CRS", [("server", r"mod_security|modsecurity"), ("x-mod-security", r".+")]),
    ("F5 BIG-IP ASM", [("server", r"big-ip|bigip"), ("x-cnection", r"close"), ("set-cookie", r"TS[0-9a-f]{8}")]),
    ("Azure Front Door / App Gateway", [("x-azure-ref", r".+"), ("server", r"microsoft-iis|azure")]),
    ("Sucuri WAF", [("x-sucuri-id", r".+"), ("server", r"sucuri")]),
    ("Fortinet FortiWeb", [("server", r"fortiweb"), ("set-cookie", r"FORTIWAF")]),
    ("Citrix NetScaler", [("set-cookie", r"ns_af=|citrix_ns_id")]),
]

# ─── Main scanner class ───────────────────────────────────────────────────────

class SecurityScanner:
    def __init__(self, base_url: str, timeout: int = 10):
        self.base_url = base_url
        self.timeout = timeout
        self.findings: list[dict] = []
        self._fid = 0

    def _next_id(self) -> str:
        self._fid += 1
        return f"F{self._fid:04d}"

    def _add_finding(self, **kwargs):
        f = {
            "id": self._next_id(),
            "cvss_score": self._sev_to_cvss(kwargs.get("severity", "INFO")),
            "confidence": kwargs.get("confidence", 80),
            **kwargs,
        }
        self.findings.append(f)
        return f

    @staticmethod
    def _sev_to_cvss(sev: str) -> float:
        return {"CRITICAL": 9.0, "HIGH": 7.5, "MEDIUM": 5.0, "LOW": 3.0, "INFO": 1.0}.get(sev, 1.0)

    async def run_all(self, crawl_result: dict, log_cb: LogCb = None) -> list[dict]:
        """Run all security checks against crawled URLs and forms."""
        urls = crawl_result.get("urls", [])
        forms = crawl_result.get("forms", [])
        js_eps = crawl_result.get("js_endpoints", [])

        async with httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=True,
            verify=False,
            headers={"User-Agent": "Mozilla/5.0 (SecurityScanner/1.0; OWASP-Audit)"},
        ) as client:

            # 1. WAF Protection & Policy Evaluation
            await self._check_waf_protection(client, self.base_url, log_cb)
            await asyncio.sleep(0.08)

            # 2. Security Headers (on base URL)
            await self._check_security_headers(client, self.base_url, log_cb)
            await asyncio.sleep(0.08)

            # 3. CORS Configuration
            await self._check_cors(client, self.base_url, log_cb)
            await asyncio.sleep(0.08)

            # 4. Cookie flags
            await self._check_cookies(client, self.base_url, log_cb)
            await asyncio.sleep(0.08)

            # 5. Server header / info disclosure on all URLs
            if log_cb: await log_cb(f"🔎 [InfoSec] Analisando vazamento de versões e headers em {len(urls)} URLs...")
            for ep in urls[:20]:
                await self._check_info_disclosure(client, ep["url"], ep.get("response_headers", {}), log_cb)
                await asyncio.sleep(0.04)

            # 6. SQLi on forms
            if forms:
                if log_cb: await log_cb(f"💉 [SQLi] Testando injeção de SQL em {len(forms)} formulários...")
                for form in forms[:15]:
                    await self._check_sqli_form(client, form, log_cb)
                    await asyncio.sleep(0.05)
            else:
                if log_cb: await log_cb("💉 [SQLi] Nenhum formulário HTML de entrada mapeado para injeção direta.")

            # 7. XSS on forms
            if forms:
                if log_cb: await log_cb(f"⚡ [XSS] Testando Cross-Site Scripting (Refletido/DOM) em {len(forms)} formulários...")
                for form in forms[:15]:
                    await self._check_xss_form(client, form, log_cb)
                    await asyncio.sleep(0.05)
            else:
                if log_cb: await log_cb("⚡ [XSS] Formulários ausentes para teste de reflexão de input.")

            # 8. SQLi on URL params
            if log_cb: await log_cb("💉 [SQLi] Validando parâmetros de URL contra SQL Injection...")
            for ep in urls[:20]:
                await self._check_sqli_url(client, ep["url"], log_cb)
                await asyncio.sleep(0.04)

            # 9. Open Redirect
            await self._check_open_redirect(client, self.base_url, log_cb)
            await asyncio.sleep(0.08)

            # 10. Sensitive files
            if log_cb: await log_cb("📂 [Exposição] Varrendo 17 arquivos e caminhos sensíveis (.env, .git, backups, configs)...")
            await self._check_sensitive_paths(client, self.base_url, log_cb)

            # 11. HTTP Methods
            await self._check_http_methods(client, self.base_url, log_cb)
            await asyncio.sleep(0.08)

        if log_cb:
            await log_cb(f"🏁 [Auditoria] Verificações finalizadas com sucesso. Total de achados documentados: {len(self.findings)}")

        return self.findings

    # ─── WAF Protection & Policy Evaluation ───────────────────────────────────

    async def _check_waf_protection(self, client: httpx.AsyncClient, url: str, log_cb: LogCb = None):
        try:
            if log_cb: await log_cb("🛡️ [WAF] Avaliando presença de Web Application Firewall & Política de Borda...")
            resp = await client.get(url)
            headers_lower = {k.lower(): v for k, v in resp.headers.items()}
            cookies_str = resp.headers.get("set-cookie", "")

            detected_waf = None
            matched_indicators = []

            # 1. Passive Header & Cookie Signature Match
            for waf_name, sigs in WAF_SIGNATURES:
                for hdr_name, pattern in sigs:
                    if hdr_name == "set-cookie":
                        if re.search(pattern, cookies_str, re.IGNORECASE):
                            detected_waf = waf_name
                            matched_indicators.append(f"Cookie: {pattern}")
                            break
                    elif hdr_name in headers_lower:
                        if re.search(pattern, headers_lower[hdr_name], re.IGNORECASE):
                            detected_waf = waf_name
                            matched_indicators.append(f"Header: {hdr_name}: {headers_lower[hdr_name]}")
                            break
                if detected_waf:
                    break

            # 2. Test WAF Behavioral Response to basic probe
            probe_url = f"{url}?waf_test_probe=%3Cscript%3Ealert(1)%3C/script%3E&union_select=1"
            probe_status = 200
            try:
                probe_resp = await client.get(probe_url)
                probe_status = probe_resp.status_code
                probe_blocked = probe_status in [403, 406, 429, 503]
            except Exception:
                probe_blocked = False

            if detected_waf:
                if log_cb:
                    await log_cb(f"✅ [WAF] WAF Detectado: {detected_waf} (Indicadores: {', '.join(matched_indicators)})")
                if not probe_blocked:
                    if log_cb:
                        await log_cb(f"⚠️ [WAF] Alerta de Política: WAF {detected_waf} está em modo permissivo (pass-through / status {probe_status}).")
                    self._add_finding(
                        title=f"WAF Policy: Web Application Firewall ({detected_waf}) em Modo Permissivo",
                        severity="LOW",
                        owasp="A05:2021 – Security Misconfiguration",
                        cwe="CWE-693",
                        affected_url=url,
                        description=f"O servidor está protegido por {detected_waf}, porém a política de inspeção permitiu passagem de requisições contendo padrões suspeitos sem bloqueio ativo (Status {probe_status}).",
                        recommendation=f"Ajustar a sensibilidade do WAF ({detected_waf}) para modo de bloqueio ativo (Blocking/Mitigation) nas categorias de OWASP Top 10 e Cross-Site Scripting.",
                        evidence=f"WAF Identificado: {detected_waf}\nIndicadores: {matched_indicators}\nResposta de Teste: HTTP {probe_status}",
                        confidence=90,
                    )
                else:
                    if log_cb:
                        await log_cb(f"🛡️ [WAF] WAF {detected_waf} bloqueou ativamente requisições de teste (HTTP {probe_status}).")
            else:
                if log_cb:
                    await log_cb("⚠️ [WAF] Nenhum Web Application Firewall (WAF) de borda detectado na aplicação.")
                self._add_finding(
                    title="Ausência de Web Application Firewall (WAF) na Camada de Borda",
                    severity="MEDIUM",
                    owasp="A05:2021 – Security Misconfiguration",
                    cwe="CWE-693",
                    affected_url=url,
                    description="Não foram detectadas assinaturas ou mecanismos de proteção ativa de WAF (como Cloudflare, AWS WAF ou ModSecurity). A aplicação recebe requisições diretamente sem filtragem perimétrica.",
                    recommendation="Implementar uma solução de Web Application Firewall (WAF) de borda com regras baseadas no OWASP Core Rule Set (CRS) para mitigar tráfego malicioso, ataques automatizados e exploração de dia zero.",
                    evidence=f"Cabeçalhos de resposta analisados sem assinaturas de WAF conhecidas.\nHeaders: {dict(resp.headers)}",
                    confidence=85,
                )
        except Exception as e:
            if log_cb: await log_cb(f"⚠️ [WAF] Erro ao avaliar WAF: {e}")

    # ─── Security Headers ──────────────────────────────────────────────────────

    async def _check_security_headers(self, client: httpx.AsyncClient, url: str, log_cb: LogCb = None):
        try:
            if log_cb: await log_cb("🔒 [Headers] Verificando 6 cabeçalhos fundamentais de segurança...")
            resp = await client.get(url)
            headers_lower = {k.lower(): v for k, v in resp.headers.items()}

            for header, meta in SECURITY_HEADERS.items():
                if header.lower() not in headers_lower:
                    if log_cb: await log_cb(f"⚠️  [Header Ausente] {header} ({meta['severity']})")
                    self._add_finding(
                        title=f"Missing Security Header: {header}",
                        severity=meta["severity"],
                        owasp=meta["owasp"],
                        cwe=meta["cwe"],
                        affected_url=url,
                        description=meta["desc"],
                        recommendation=meta["rec"],
                        evidence=f"Header '{header}' absent from response.\nResponse headers: {dict(resp.headers)}",
                    )
                else:
                    if log_cb: await log_cb(f"✅ [Header Conforme] {header}")
        except Exception:
            pass

    # ─── CORS ─────────────────────────────────────────────────────────────────

    async def _check_cors(self, client: httpx.AsyncClient, url: str, log_cb: LogCb = None):
        try:
            if log_cb: await log_cb("🌐 [CORS] Testando reflexão de Origin e política de credenciais...")
            resp = await client.get(url, headers={"Origin": "https://evil-attacker.com"})
            acao = resp.headers.get("access-control-allow-origin", "")
            acac = resp.headers.get("access-control-allow-credentials", "")

            if acao == "*":
                if log_cb: await log_cb("⚠️  [CORS] Access-Control-Allow-Origin: * permitido.")
                self._add_finding(
                    title="CORS Wildcard Origin Allowed",
                    severity="MEDIUM",
                    owasp="A05:2021 – Security Misconfiguration",
                    cwe="CWE-942",
                    affected_url=url,
                    description="The server responds with Access-Control-Allow-Origin: * allowing any origin to make cross-origin requests.",
                    recommendation="Restrict CORS to specific trusted origins. Never use '*' with credentials.",
                    evidence=f"Request: Origin: https://evil-attacker.com\nResponse: Access-Control-Allow-Origin: {acao}",
                )
            elif acao == "https://evil-attacker.com":
                sev = "HIGH" if acac.lower() == "true" else "MEDIUM"
                if log_cb: await log_cb(f"⚠️  [CORS] Origem arbitrária refletida (Severidade {sev}).")
                self._add_finding(
                    title="CORS Arbitrary Origin Reflected" + (" with Credentials" if sev == "HIGH" else ""),
                    severity=sev,
                    owasp="A05:2021 – Security Misconfiguration",
                    cwe="CWE-942",
                    affected_url=url,
                    description=f"Server reflects arbitrary Origin header in Access-Control-Allow-Origin. "
                                f"{'Combined with Allow-Credentials: true, this allows authenticated cross-origin requests from malicious sites.' if sev == 'HIGH' else ''}",
                    recommendation="Implement an explicit allowlist of trusted origins. Validate Origin against the list before reflecting.",
                    evidence=f"Request: Origin: https://evil-attacker.com\n"
                             f"Response: Access-Control-Allow-Origin: {acao}\n"
                             f"Response: Access-Control-Allow-Credentials: {acac}",
                )
            else:
                if log_cb: await log_cb("✅ [CORS] Política de origem cruzada restritiva e conforme.")
        except Exception:
            pass

    # ─── Cookies ──────────────────────────────────────────────────────────────

    async def _check_cookies(self, client: httpx.AsyncClient, url: str, log_cb: LogCb = None):
        try:
            if log_cb: await log_cb("🍪 [Cookies] Inspecionando atributos Secure, HttpOnly e SameSite...")
            resp = await client.get(url)
            cookie_count = len(resp.cookies.jar)
            if log_cb: await log_cb(f"🍪 [Cookies] {cookie_count} cookies de sessão identificados.")
            for cookie in resp.cookies.jar:
                issues = []
                if not cookie.secure:
                    issues.append("missing Secure flag")
                if not cookie.has_nonstandard_attr("HttpOnly"):
                    issues.append("missing HttpOnly flag")
                samesite = cookie.get_nonstandard_attr("SameSite", "")
                if not samesite:
                    issues.append("missing SameSite attribute")

                if issues:
                    self._add_finding(
                        title=f"Insecure Cookie: {cookie.name}",
                        severity="MEDIUM",
                        owasp="A05:2021 – Security Misconfiguration",
                        cwe="CWE-614",
                        affected_url=url,
                        description=f"Cookie '{cookie.name}' has security issues: {', '.join(issues)}.",
                        recommendation=f"Set-Cookie: {cookie.name}=...; Secure; HttpOnly; SameSite=Strict",
                        evidence=f"Set-Cookie header for '{cookie.name}': {issues}",
                    )
        except Exception:
            pass

    # ─── Info Disclosure ──────────────────────────────────────────────────────

    async def _check_info_disclosure(self, client: httpx.AsyncClient, url: str, resp_headers: dict, log_cb: LogCb = None):
        # Server header version disclosure
        server = resp_headers.get("server", resp_headers.get("Server", ""))
        if server and any(c.isdigit() for c in server):
            self._add_finding(
                title=f"Server Version Disclosure via Header",
                severity="LOW",
                owasp="A05:2021 – Security Misconfiguration",
                cwe="CWE-200",
                affected_url=url,
                description=f"The Server header reveals version information: '{server}'. This helps attackers fingerprint the technology stack.",
                recommendation="Configure the server to suppress version information. E.g. nginx: server_tokens off;",
                evidence=f"Server: {server}",
            )
        # X-Powered-By
        powered = resp_headers.get("x-powered-by", resp_headers.get("X-Powered-By", ""))
        if powered:
            self._add_finding(
                title="Technology Fingerprinting via X-Powered-By Header",
                severity="LOW",
                owasp="A05:2021 – Security Misconfiguration",
                cwe="CWE-200",
                affected_url=url,
                description=f"The X-Powered-By header exposes technology: '{powered}'.",
                recommendation="Remove X-Powered-By header from responses.",
                evidence=f"X-Powered-By: {powered}",
            )

        # Check response body for info disclosure
        try:
            resp = await client.get(url)
            text = resp.text[:5000]
            for pattern, label in INFO_DISCLOSURE_PATTERNS:
                match = re.search(pattern, text, re.IGNORECASE)
                if match and label not in [f.get("title", "") for f in self.findings]:
                    self._add_finding(
                        title=f"Information Disclosure: {label}",
                        severity="MEDIUM" if "trace" in label.lower() or "error" in label.lower() else "LOW",
                        owasp="A05:2021 – Security Misconfiguration",
                        cwe="CWE-200",
                        affected_url=url,
                        description=f"Sensitive information found in response: {label}.",
                        recommendation="Ensure error pages do not reveal internal implementation details. Use generic error messages in production.",
                        evidence=f"Pattern matched: {match.group(0)[:200]}",
                    )
        except Exception:
            pass

    # ─── SQL Injection (Forms) ────────────────────────────────────────────────

    async def _check_sqli_form(self, client: httpx.AsyncClient, form: dict, log_cb: LogCb = None):
        action = form["action"]
        method = form["method"]
        inputs = form["inputs"]

        for payload in SQLI_PAYLOADS[:3]:
            data = {inp["name"]: payload for inp in inputs if inp["name"]}
            try:
                if method == "POST":
                    resp = await client.post(action, data=data)
                else:
                    resp = await client.get(action, params=data)

                text = resp.text
                for pattern in SQLI_ERROR_PATTERNS:
                    if re.search(pattern, text, re.IGNORECASE):
                        self._add_finding(
                            title="SQL Injection — Error-Based",
                            severity="CRITICAL",
                            owasp="A03:2021 – Injection",
                            cwe="CWE-89",
                            affected_url=action,
                            description=f"SQL error detected in response when injecting SQL payload into form fields. The application may be vulnerable to SQL Injection.",
                            recommendation="Use parameterized queries / prepared statements. Implement input validation. Use an ORM.",
                            evidence=f"Payload: {payload}\nForm: {action}\nSQLi error pattern matched in response: '{re.search(pattern, text, re.IGNORECASE).group(0)[:200]}'",
                            confidence=90,
                        )
                        if log_cb: await log_cb(f"⚠️  SQL Injection found at {action}")
                        return
            except Exception:
                pass

    # ─── SQL Injection (URL params) ───────────────────────────────────────────

    async def _check_sqli_url(self, client: httpx.AsyncClient, url: str, log_cb: LogCb = None):
        parsed = urlparse(url)
        if not parsed.query:
            return

        from urllib.parse import parse_qs, urlencode
        params = parse_qs(parsed.query, keep_blank_values=True)
        if not params:
            return

        for payload in SQLI_PAYLOADS[:2]:
            test_params = {k: [payload] for k in params}
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"
            try:
                resp = await client.get(test_url)
                for pattern in SQLI_ERROR_PATTERNS:
                    if re.search(pattern, resp.text, re.IGNORECASE):
                        self._add_finding(
                            title="SQL Injection — URL Parameter",
                            severity="CRITICAL",
                            owasp="A03:2021 – Injection",
                            cwe="CWE-89",
                            affected_url=url,
                            description="SQL error detected when injecting payload into URL parameters.",
                            recommendation="Use parameterized queries. Never concatenate user input into SQL strings.",
                            evidence=f"Test URL: {test_url}\nPayload: {payload}\nError: {re.search(pattern, resp.text, re.IGNORECASE).group(0)[:200]}",
                            confidence=85,
                        )
                        if log_cb: await log_cb(f"⚠️  SQL Injection (URL param) at {url}")
                        return
            except Exception:
                pass

    # ─── XSS (Forms) ─────────────────────────────────────────────────────────

    async def _check_xss_form(self, client: httpx.AsyncClient, form: dict, log_cb: LogCb = None):
        action = form["action"]
        method = form["method"]
        inputs = form["inputs"]

        for payload in XSS_PAYLOADS[:2]:
            data = {inp["name"]: payload for inp in inputs if inp["name"]}
            try:
                if method == "POST":
                    resp = await client.post(action, data=data)
                else:
                    resp = await client.get(action, params=data)

                if payload in resp.text or payload.lower() in resp.text.lower():
                    self._add_finding(
                        title="Cross-Site Scripting (XSS) — Reflected",
                        severity="HIGH",
                        owasp="A03:2021 – Injection",
                        cwe="CWE-79",
                        affected_url=action,
                        description="XSS payload reflected in the response without encoding. An attacker can inject malicious scripts that execute in victims' browsers.",
                        recommendation="Implement output encoding (HTML entity encoding). Use Content-Security-Policy. Use a modern framework with auto-escaping.",
                        evidence=f"Payload: {payload}\nForm action: {action}\nPayload found unencoded in response body.",
                        confidence=85,
                    )
                    if log_cb: await log_cb(f"⚠️  XSS found at {action}")
                    return
            except Exception:
                pass

    # ─── Open Redirect ────────────────────────────────────────────────────────

    async def _check_open_redirect(self, client: httpx.AsyncClient, url: str, log_cb: LogCb = None):
        if log_cb: await log_cb("🔀 [Redirect] Testando vetores de Open Redirect em parâmetros comuns...")
        redirect_params = ["redirect", "url", "next", "return", "returnUrl", "goto", "dest", "destination", "target"]
        evil_url = "https://evil-attacker.com"

        for param in redirect_params:
            test_url = f"{url}?{param}={evil_url}"
            try:
                resp = await client.get(test_url, follow_redirects=False)
                location = resp.headers.get("location", "")
                if evil_url in location:
                    if log_cb: await log_cb(f"⚠️  [Redirect] Open Redirect vulnerável no parâmetro '{param}'!")
                    self._add_finding(
                        title=f"Open Redirect via '{param}' Parameter",
                        severity="MEDIUM",
                        owasp="A01:2021 – Broken Access Control",
                        cwe="CWE-601",
                        affected_url=url,
                        description=f"The application redirects to arbitrary URLs via the '{param}' parameter, enabling phishing attacks.",
                        recommendation=f"Validate redirect URLs against an allowlist of trusted destinations. Reject external redirects.",
                        evidence=f"Request: GET {test_url}\nResponse: Location: {location}",
                    )
                    return
            except Exception:
                pass

    # ─── Sensitive Paths ──────────────────────────────────────────────────────

    async def _check_sensitive_paths(self, client: httpx.AsyncClient, base_url: str, log_cb: LogCb = None):
        sensitive = [
            ("/.env", "Environment file exposed", "CRITICAL"),
            ("/.git/config", "Git repository exposed", "HIGH"),
            ("/admin", "Admin panel accessible", "HIGH"),
            ("/phpinfo.php", "phpinfo() exposed", "HIGH"),
            ("/wp-admin", "WordPress admin accessible", "MEDIUM"),
            ("/api/swagger.json", "API documentation exposed", "LOW"),
            ("/api/docs", "API documentation exposed", "LOW"),
            ("/swagger-ui.html", "Swagger UI exposed", "LOW"),
            ("/actuator", "Spring Boot Actuator exposed", "HIGH"),
            ("/actuator/env", "Spring Boot Actuator env exposed", "CRITICAL"),
            ("/server-status", "Apache server-status exposed", "MEDIUM"),
            ("/debug", "Debug endpoint exposed", "HIGH"),
            ("/console", "Admin console exposed", "HIGH"),
            ("/.DS_Store", "macOS metadata file exposed", "LOW"),
            ("/backup.zip", "Backup file exposed", "CRITICAL"),
            ("/robots.txt", "Robots.txt (info gathering)", "INFO"),
            ("/sitemap.xml", "Sitemap (info gathering)", "INFO"),
        ]

        for path, desc, severity in sensitive:
            try:
                resp = await client.get(f"{base_url.rstrip('/')}{path}", follow_redirects=False)
                if log_cb:
                    if resp.status_code == 200 and severity != "INFO":
                        await log_cb(f"⚠️  [Exposição] Caminho sensível detectado: {path} (HTTP {resp.status_code})")
                    elif resp.status_code != 404:
                        await log_cb(f"📂 [Exposição] {path} → HTTP {resp.status_code}")

                if resp.status_code in (200, 301, 302, 403):
                    if resp.status_code == 200 and severity not in ("INFO",):
                        self._add_finding(
                            title=f"Sensitive Path Accessible: {path}",
                            severity=severity,
                            owasp="A05:2021 – Security Misconfiguration",
                            cwe="CWE-548",
                            affected_url=f"{base_url.rstrip('/')}{path}",
                            description=f"{desc}. Path '{path}' returned HTTP {resp.status_code}.",
                            recommendation=f"Restrict access to '{path}'. Remove or protect sensitive files from public access.",
                            evidence=f"GET {base_url.rstrip('/')}{path}\nHTTP {resp.status_code}\nBody preview: {resp.text[:200]}",
                            confidence=95,
                        )
                    elif severity == "INFO" and resp.status_code == 200:
                        self._add_finding(
                            title=f"Information Gathering: {path} accessible",
                            severity="INFO",
                            owasp="A05:2021 – Security Misconfiguration",
                            cwe="CWE-200",
                            affected_url=f"{base_url.rstrip('/')}{path}",
                            description=f"{desc}.",
                            recommendation="Review content and restrict if necessary.",
                            evidence=f"HTTP 200 at {path}",
                            confidence=100,
                        )
                await asyncio.sleep(0.04)
            except Exception:
                pass

    # ─── HTTP Methods ─────────────────────────────────────────────────────────

    async def _check_http_methods(self, client: httpx.AsyncClient, url: str, log_cb: LogCb = None):
        try:
            if log_cb: await log_cb("📡 [Métodos] Avaliando métodos HTTP perigosos habilitados via OPTIONS...")
            resp = await client.options(url)
            allow = resp.headers.get("allow", resp.headers.get("Allow", ""))
            if log_cb and allow:
                await log_cb(f"📡 [Métodos] Servidor reportou métodos permitidos: {allow}")
            dangerous = [m for m in ["TRACE", "DELETE", "PUT", "PATCH"] if m in allow.upper()]
            if dangerous:
                if log_cb: await log_cb(f"⚠️  [Métodos] Métodos perigosos habilitados: {', '.join(dangerous)}")
                self._add_finding(
                    title=f"Dangerous HTTP Methods Allowed: {', '.join(dangerous)}",
                    severity="MEDIUM",
                    owasp="A05:2021 – Security Misconfiguration",
                    cwe="CWE-16",
                    affected_url=url,
                    description=f"The server allows potentially dangerous HTTP methods: {', '.join(dangerous)}. TRACE can be used for Cross-Site Tracing (XST) attacks.",
                    recommendation="Disable unused HTTP methods. Only allow GET and POST unless explicitly needed.",
                    evidence=f"OPTIONS {url}\nAllow: {allow}",
                )
            else:
                if log_cb: await log_cb("✅ [Métodos] Nenhum método perigoso habilitado.")
        except Exception:
            pass
