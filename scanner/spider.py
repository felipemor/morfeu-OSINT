"""
Spider — crawls URLs recursively finding all links, forms, JS endpoints
"""
import asyncio
import re
from urllib.parse import urljoin, urlparse, urlencode
from typing import Optional
import httpx
from bs4 import BeautifulSoup


HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 (OWASP-Security-Auditor/1.0)",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "Accept-Language": "pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7",
}

JS_API_PATTERN = re.compile(
    r'(?:fetch|axios\.(?:get|post|put|delete|patch)|XMLHttpRequest)\s*\(\s*[\'"]([^\'"]+)[\'"]',
    re.IGNORECASE
)

COMMON_PROBE_PATHS = [
    "/",
    "/login",
    "/portal",
    "/auth",
    "/api",
    "/servicos",
    "/produtos",
    "/contato",
    "/sobre",
    "/atendimento",
    "/politica-de-privacidade",
    "/termos-de-uso",
    "/faq",
    "/app",
]


class Spider:
    def __init__(self, base_url: str, max_depth: int = 3, max_urls: int = 150, timeout: int = 10):
        self.base_url = base_url.rstrip("/")
        self.base_host = urlparse(base_url).netloc
        self.base_scheme = urlparse(base_url).scheme
        self.max_depth = max_depth
        self.max_urls = max_urls
        self.timeout = timeout
        self.visited: set[str] = set()
        self.discovered: list[dict] = []
        self.forms: list[dict] = []
        self.js_endpoints: list[str] = []
        self.errors: list[str] = []

    async def crawl(self, log_cb=None) -> dict:
        """Main crawl entry point. Returns all discovered URLs and forms."""
        async with httpx.AsyncClient(
            headers=HEADERS,
            timeout=self.timeout,
            follow_redirects=True,
            verify=False,
            limits=httpx.Limits(max_connections=10, max_keepalive_connections=5),
        ) as client:
            # 1. Crawl base URL
            await self._crawl_url(client, self.base_url, depth=0, log_cb=log_cb)

            # 2. Probe common paths to uncover endpoints on SPAs
            if log_cb:
                await log_cb(f"🕷️ [Spider] Mapeando rotas e páginas comuns da aplicação...")

            for p in COMMON_PROBE_PATHS:
                if len(self.visited) >= self.max_urls:
                    break
                full_p = f"{self.base_url}{p}"
                if full_p not in self.visited:
                    await self._crawl_url(client, full_p, depth=1, log_cb=log_cb)
                    await asyncio.sleep(0.04)

        return {
            "urls": self.discovered,
            "forms": self.forms,
            "js_endpoints": list(set(self.js_endpoints)),
            "total": len(self.discovered),
        }

    async def _crawl_url(self, client: httpx.AsyncClient, url: str, depth: int, log_cb=None):
        if depth > self.max_depth or len(self.visited) >= self.max_urls:
            return
        if url in self.visited:
            return
        if not self._in_scope(url):
            return

        self.visited.add(url)

        try:
            resp = await client.get(url)
            content_type = resp.headers.get("content-type", "")

            endpoint = {
                "url": url,
                "method": "GET",
                "status_code": resp.status_code,
                "content_type": content_type,
                "response_headers": dict(resp.headers),
                "content_length": len(resp.content),
                "depth": depth,
            }

            if resp.status_code != 404:
                self.discovered.append(endpoint)
                if log_cb:
                    await log_cb(f"🕷️ [Spider] [{resp.status_code}] {url} ({len(resp.content)} bytes)")

            # Only parse HTML for further links
            if "text/html" not in content_type:
                return

            soup = BeautifulSoup(resp.text, "lxml")

            # Extract links
            links = set()
            for tag in soup.find_all(["a", "link"], href=True):
                abs_url = urljoin(url, tag["href"])
                abs_url = abs_url.split("#")[0].split("?")[0]
                if self._in_scope(abs_url) and abs_url not in self.visited:
                    links.add(abs_url)

            # Extract forms
            for form in soup.find_all("form"):
                action = form.get("action", url)
                method = form.get("method", "GET").upper()
                abs_action = urljoin(url, action)
                inputs = []
                for inp in form.find_all(["input", "textarea", "select"]):
                    inputs.append({
                        "name": inp.get("name", ""),
                        "type": inp.get("type", "text"),
                        "value": inp.get("value", ""),
                    })
                if inputs:
                    form_entry = {
                        "action": abs_action,
                        "method": method,
                        "inputs": inputs,
                        "source_url": url,
                    }
                    self.forms.append(form_entry)
                    if log_cb:
                        await log_cb(f"📋 [Formulário] Detectado form {method} em {abs_action} ({len(inputs)} campos)")

            # Extract JS API endpoints
            for script in soup.find_all("script"):
                if script.string:
                    for match in JS_API_PATTERN.findall(script.string):
                        if match.startswith("/") or match.startswith("http"):
                            ep = urljoin(url, match)
                            self.js_endpoints.append(ep)
                            if log_cb:
                                await log_cb(f"⚡ [API] Endpoint JS identificado: {ep}")

            # Also look for script src files
            for script in soup.find_all("script", src=True):
                src = urljoin(url, script["src"])
                if self._in_scope(src) and src not in self.visited:
                    links.add(src)

            # Crawl discovered links concurrently (batches of 4)
            link_list = list(links)[:20]
            for i in range(0, len(link_list), 4):
                if len(self.visited) >= self.max_urls:
                    break
                batch = link_list[i:i+4]
                await asyncio.gather(*[
                    self._crawl_url(client, lnk, depth + 1, log_cb)
                    for lnk in batch
                ], return_exceptions=True)

        except httpx.TimeoutException:
            self.errors.append(f"Timeout: {url}")
            if log_cb: await log_cb(f"⚠️ [Timeout] {url}")
        except httpx.ConnectError as e:
            self.errors.append(f"ConnectError: {url} — {e}")
        except Exception as e:
            self.errors.append(f"Error: {url} — {e}")

    def _in_scope(self, url: str) -> bool:
        try:
            parsed = urlparse(url)
            base_clean = self.base_host.lower().replace("www.", "")
            url_clean = parsed.netloc.lower().replace("www.", "")

            in_domain = (url_clean == base_clean or parsed.netloc.lower().endswith("." + base_clean))
            not_media = not any(ext in url.lower() for ext in [
                ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
                ".css", ".woff", ".woff2", ".ttf", ".eot", ".mp4",
                ".pdf", ".zip", ".gz", ".tar"
            ])
            return in_domain and parsed.scheme in ("http", "https") and not_media
        except Exception:
            return False
