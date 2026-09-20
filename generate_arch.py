content = r"""# 🏗️ ARCHITECTURE — morfeusec OSINT
> Documentação técnica detalhada de todos os componentes, camadas, serviços, fluxos de dados e tecnologias da plataforma.

---

## 📑 Índice

1. [Visão Geral da Arquitetura](#1-visão-geral-da-arquitetura)
2. [Diagrama de Componentes — Visão Macro](#2-diagrama-de-componentes--visão-macro)
3. [Camada 1 — Frontend (Next.js 14)](#3-camada-1--frontend-nextjs-14)
4. [Camada 2 — Backend API (FastAPI)](#4-camada-2--backend-api-fastapi)
5. [Camada 3 — Motor de Agentes Inteligentes (Celery + LLM)](#5-camada-3--motor-de-agentes-inteligentes-celery--llm)
6. [Camada 4 — Scanner de Segurança Standalone](#6-camada-4--scanner-de-segurança-standalone)
7. [Camada 5 — Persistência (PostgreSQL + Redis)](#7-camada-5--persistência-postgresql--redis)
8. [Camada 6 — Observabilidade (Prometheus + Grafana + Flower)](#8-camada-6--observabilidade-prometheus--grafana--flower)
9. [Camada 7 — Ambiente de Laboratório Isolado (OWASP Juice Shop)](#9-camada-7--ambiente-de-laboratório-isolado-owasp-juice-shop)
10. [Fluxo de Dados — Autenticação Zero-Trust](#10-fluxo-de-dados--autenticação-zero-trust)
11. [Fluxo de Dados — Varredura OSINT Completa](#11-fluxo-de-dados--varredura-osint-completa)
12. [Fluxo de Dados — Mobile Pentest APK/IPA](#12-fluxo-de-dados--mobile-pentest-apkipa)
13. [Fluxo de Dados — 32 Controles de Segurança BACEN](#13-fluxo-de-dados--32-controles-de-segurança-bacen)
14. [Fluxo de Dados — Geração de Laudos em PDF](#14-fluxo-de-dados--geração-de-laudos-em-pdf)
15. [Rede Docker e Mapeamento de Portas](#15-rede-docker-e-mapeamento-de-portas)
16. [Segurança e Controles de Acesso](#16-segurança-e-controles-de-acesso)
17. [Tabela de Tecnologias Completa](#17-tabela-de-tecnologias-completa)

---

## 1. Visão Geral da Arquitetura

O **morfeusec OSINT** adota o padrão **Decoupled Micro-Services & Async Event-Driven Architecture**, dividido em **7 camadas horizontais independentes**:

```
 ┌────────────────────────────────────────────────────────────────────────────┐
 │               CLIENTE (Navegador — Chrome / Firefox / Edge)                │
 └──────────────────────────────────┬─────────────────────────────────────────┘
                                    │  HTTPS + WebSocket (ws://)
 ┌──────────────────────────────────▼─────────────────────────────────────────┐
 │  CAMADA 1  FRONTEND   Next.js 14 + TypeScript + Tailwind CSS               │
 │            Porta: 3000 / 3005                                               │
 └──────────────────────────────────┬─────────────────────────────────────────┘
                                    │  REST API JSON + WebSocket
 ┌──────────────────────────────────▼─────────────────────────────────────────┐
 │  CAMADA 2  BACKEND API   FastAPI + Uvicorn + Python 3.11+                   │
 │            Porta: 8000  |  /api/v1/* + /ws/* + /metrics + /health          │
 └──────────┬───────────────────────┬─────────────────────────────────────────┘
            │ Celery Dispatch        │ SQL async (asyncpg)
 ┌──────────▼───────────┐  ┌────────▼────────────────────────────────────────┐
 │  CAMADA 3            │  │  CAMADA 5  BANCO DE DADOS                       │
 │  AGENTES (Celery)    │  │  PostgreSQL 16  +  Redis 7 (Cache/Queue)        │
 │  Worker + Beat       │  │  Porta: 5432  /  Porta: 6379                    │
 └──────────┬───────────┘  └─────────────────────────────────────────────────┘
            │ HTTP Interno
 ┌──────────▼───────────────────────────────────────────────────────────────┐
 │  CAMADA 4  SCANNER STANDALONE   FastAPI + Python                          │
 │  OSINT Engine + Mobile Pentest Engine + 32 Controles Engine               │
 └──────────┬───────────────────────────────────────────────────────────────┘
            │
 ┌──────────▼──────────┐   ┌─────────────────────────────────────────────────┐
 │  CAMADA 6           │   │  CAMADA 7  LAB ISOLADO                          │
 │  OBSERVABILIDADE    │   │  Docker bridge internal (sem internet)           │
 │  Prometheus :9090   │   │  OWASP Juice Shop :3002                          │
 │  Grafana    :3001   │   │  Target de testes autônomos isolados             │
 │  Flower     :5555   │   └─────────────────────────────────────────────────┘
 └─────────────────────┘
```

---

## 2. Diagrama de Componentes — Visão Macro

```
           ┌───────────────────────────────────────────────────────────┐
           │              morfeusec OSINT — Serviços Ativos            │
           └────────────────────────────┬──────────────────────────────┘
                                        │
          ┌─────────────────────────────┴──────────────────────────────┐
          │                                                             │
  ┌───────▼──────────────┐                               ┌────────────▼────────────┐
  │  FRONTEND (Next.js)  │                               │  OBSERVABILIDADE        │
  │                      │                               │  Prometheus + Grafana   │
  │  /login              │                               │  Flower (Celery UI)     │
  │  /dashboard          │                               └─────────────────────────┘
  │  /mobile-dashboard   │
  │  /mobile-pentest     │
  │  /osint              │
  │  /security-controls  │
  │  /attack-surface     │
  │  /reports            │
  │  /projects           │
  │  /scan               │
  │  /findings           │
  │  /audit-logs         │
  │                      │
  │  PDF Engine: pdf-lib │
  │  QR Engine: qrcode   │
  └──────────┬───────────┘
             │ HTTP + WebSocket
             ▼
  ┌──────────────────────────────────────────────────────────┐
  │  BACKEND API (FastAPI :8000)                             │
  │                                                          │
  │  /api/v1/auth/*          JWT + bcrypt + 2FA TOTP        │
  │  /api/v1/projects/*      CRUD escopos de pentest        │
  │  /api/v1/scans/*         Jobs de varredura              │
  │  /api/v1/findings/*      Vulnerabilidades + evidências  │
  │  /api/v1/assets/*        Inventário de ativos           │
  │  /api/v1/osint/*         Trigger OSINT                  │
  │  /api/v1/mobile/*        Upload + análise APK/IPA       │
  │  /api/v1/security-controls/* Auditoria 32 controles     │
  │  /api/v1/reports/*       Geração de relatórios          │
  │  /api/v1/agents/*        Controle de agentes AI         │
  │  /api/v1/audit/*         Trilha de auditoria            │
  │  /ws/*                   WebSocket streaming            │
  │  /metrics                Prometheus endpoint            │
  │  /health                 Health check                   │
  │                                                          │
  │  MIDDLEWARE STACK:                                       │
  │  CORS > GZip > Request-ID > Security Headers > JWT      │
  └──────────┬──────────────────────────────┬───────────────┘
             │                              │
             ▼                              ▼
  ┌──────────────────────┐     ┌────────────────────────────┐
  │  AGENTES CELERY      │     │  PERSISTÊNCIA              │
  │                      │     │                            │
  │  Orchestrator        │     │  PostgreSQL 16             │
  │  Planner Agent       │     │  users, projects, scans    │
  │  Recon Agent         │     │  findings, assets          │
  │  Crawler Agent       │     │  mobile_apps               │
  │  Vuln Agent          │     │  security_controls         │
  │  Browser Agent       │     │  reports, audit_logs       │
  │  Screenshot Agent    │     │                            │
  │  API Agent           │     │  Redis 7 (512MB LRU)       │
  │  Report Agent        │     │  Task Queue (Celery)       │
  │                      │     │  DNS Cache (1h TTL)        │
  │  LLM Providers:      │     │  Rate Limiting             │
  │  Ollama / OpenAI /   │     │  Session Store (JWT)       │
  │  Anthropic / Gemini  │     └────────────────────────────┘
  └──────────────────────┘
```

---

## 3. Camada 1 — Frontend (Next.js 14)

### Estrutura de Diretórios

```
frontend/src/
├── app/
│   ├── layout.tsx                     # Root layout — providers globais
│   ├── page.tsx                       # Redirect root para /login
│   ├── globals.css                    # Design system Dark Cyber (CSS vars + Tailwind)
│   ├── login/page.tsx                 # Auth Zero-Trust (2FA TOTP + QR Code 2D real)
│   └── (app)/
│       ├── layout.tsx                 # Layout protegido (Sidebar + Navbar)
│       ├── dashboard/page.tsx         # KPIs executivos, radar de risco, CVSS charts
│       ├── mobile-dashboard/page.tsx  # Fleet Threat Index + Radar MASVS + CI/CD Gates
│       ├── mobile-pentest/page.tsx    # Upload batch APK/IPA + análise SAST/DAST
│       ├── osint/page.tsx             # DNS DoH + CT Logs + WAF + Dorks + S3
│       ├── security-controls/page.tsx # 32 controles BACEN/CIS + laudo PDF
│       ├── attack-surface/page.tsx    # Grafo interativo D3 de superfície de ataque
│       ├── reports/page.tsx           # Central de dossiês e downloads
│       ├── projects/page.tsx          # Gestão de projetos e escopos
│       ├── findings/page.tsx          # Vulnerabilidades abertas com filtro/sorter
│       ├── scan/page.tsx              # Fila de scans ativos e histórico
│       └── audit-logs/page.tsx        # Trilha de auditoria da plataforma
├── components/
│   ├── layout/                        # Sidebar, Navbar, header responsivo
│   └── assistant/                     # Painel AI Assistant (Felipinho)
└── lib/
    ├── api.ts                         # Axios client + interceptadores JWT + authApi
    ├── pdf-lib-security-controls.ts   # PDF vetorial 3 páginas — 32 controles BACEN
    ├── pdf-lib-mobile.ts              # PDF vetorial — Mobile Pentest MASVS v2.0
    ├── security-controls-pdf-fallback.ts # Fallback PDF via browser print API
    ├── mobile-pdf-fallback.ts         # Fallback PDF mobile via browser
    └── react-query-provider.tsx       # TanStack Query provider global
```

### Design System — Tema Dark Cyber

```css
/* globals.css — Paleta de cores e tokens */
--bg-primary:   #080c18   /* Fundo escuro profundo */
--bg-card:      #0f172a   /* Cards, painéis, modais */
--bg-border:    #1e293b   /* Bordas e divisores */
--accent-cyan:  #00e676   /* Verde cibernético (destaque primário) */
--accent-blue:  #38bdf8   /* Azul secundário */
--text-primary: #f1f5f9   /* Texto principal */
--text-muted:   #64748b   /* Texto secundário e labels */

/* Fonte: Inter — Google Fonts */
/* Animações customizadas: animate-scan, animate-fade-in */
```

### Tecnologias do Frontend

| Tecnologia | Versão | Função |
|---|---|---|
| Next.js | 14.2.13 | SSR/SSG com App Router e Route Groups |
| React | 18.3.1 | UI reativa com hooks e Suspense |
| TypeScript | 5.6.2 | Tipagem estática de todos os modelos e componentes |
| Tailwind CSS | 3.4.12 | Sistema de utilitários + tema Dark Cyber customizado |
| pdf-lib | 1.17.1 | Geração binária de PDF vetorial no cliente (sem servidor) |
| qrcode | 1.5.4 | Renderização de QR Code 2D (ECC Level M) — iOS/Android |
| Recharts | 2.12.7 | Radar MASVS, barras de severidade, área temporal, rosca |
| D3 | 7.9.0 | Grafo de superfície de ataque |
| Lucide React | 0.441.0 | Ícones vetoriais SVG |
| Axios | 1.7.7 | HTTP client com interceptadores de auth JWT |
| TanStack Query | 5.56.2 | Cache, refetch automático e estado de queries |
| React Hot Toast | 2.4.1 | Notificações de eventos de varredura e auth |
| Framer Motion | 11.5.4 | Animações de entrada e microinterações |
| date-fns | 3.6.0 | Formatação de datas nos relatórios |
| js-cookie | 3.0.5 | Gerenciamento seguro de sessão no cliente |
| Zod + react-hook-form | 3.23 / 7.53 | Formulários tipados com validação de esquema |
| clsx | 2.1.1 | Composição condicional de classes Tailwind |
| prismjs | 1.29.0 | Highlight de código em evidências técnicas |

---

## 4. Camada 2 — Backend API (FastAPI)

### Estrutura de Diretórios

```
backend/app/
├── main.py                    # Entry point: app factory, middleware, Prometheus, lifespan
├── models.py                  # SQLAlchemy ORM (40k+ bytes): User, Project, Scan, Finding...
├── api/
│   ├── deps.py                # Dependências compartilhadas (get_db, get_current_user)
│   ├── websocket.py           # WebSocket streaming em tempo real para scan progress
│   └── v1/
│       ├── __init__.py        # Agregador de todos os routers API v1
│       ├── auth.py            # POST /auth/login, POST /auth/refresh
│       ├── projects.py        # CRUD projetos (GET/POST/PUT/DELETE /projects/*)
│       ├── scans.py           # GET/POST /scans/*, GET /scans/{id}/status
│       ├── findings.py        # CRUD vulnerabilidades + evidências
│       ├── assets.py          # GET/POST /assets/*, inventário de domínios/IPs
│       ├── osint.py           # POST /osint/scan (trigger varredura OSINT)
│       ├── mobile_pentest.py  # POST /mobile/upload, POST /mobile/analyze
│       ├── security_controls.py # POST /security-controls/test-all, /report/pdf
│       ├── reports.py         # GET/POST /reports/*, download de PDFs e xlsx
│       ├── agents.py          # GET/POST /agents/*, controle de agentes autônomos
│       ├── audit.py           # GET /audit/*, trilha imutável de eventos
│       ├── users.py           # CRUD /users/*
│       ├── approvals.py       # Fluxo de aprovação para scans invasivos
│       ├── evidence.py        # Upload e gestão de evidências (screenshots, HAR)
│       ├── scopes.py          # Definição de escopos autorizados por projeto
│       ├── topology.py        # Mapa topológico de rede gerado pelo Recon Agent
│       ├── nl_assistant.py    # Interface em linguagem natural do AI Assistant
│       └── felipinho.py       # Endpoint do assistente personalizado Felipinho
├── core/
│   ├── config.py              # Configurações via pydantic-settings (lê .env)
│   ├── database.py            # Engine asyncpg + AsyncSession factory
│   ├── logging.py             # Structlog JSON com contextvars por request
│   ├── metrics.py             # Contadores e histogramas Prometheus customizados
│   ├── scope_validator.py     # Valida targets contra escopo autorizado (CRÍTICO)
│   └── security.py            # bcrypt hash, JWT encode/decode, TOTP validation
├── services/
│   ├── mobile_pentest_service.py  # Motor SAST Android/iOS (44k bytes)
│   ├── security_controls_service.py # 32 controles automatizados (63k bytes)
│   ├── osint_service.py            # OSINT perimeter recon (24k bytes)
│   ├── agent_service.py            # Orquestração dos agentes AI (17k bytes)
│   ├── attack_surface.py           # Construção do grafo de superfície de ataque
│   ├── risk_engine.py              # Cálculo de risk score e CVSS scoring
│   ├── compliance.py               # Mapeamento BACEN/NIST/CIS Controls
│   ├── evidence_service.py         # Gestão de screenshots e evidências
│   ├── finding_pipeline.py         # Pipeline de deduplicação de findings
│   ├── hypothesis_engine.py        # Geração de hipóteses de ataque via LLM
│   ├── baseline_drift_service.py   # Detecção de drift de postura de segurança
│   ├── security_controls_pdf.py    # Geração de PDF server-side (ReportLab)
│   ├── felipinho_service.py        # Serviço do assistente AI Felipinho
│   ├── nl_planner.py               # Planejamento em linguagem natural via LLM
│   └── kill_switch.py              # Interrupção imediata de todos os scans ativos
└── agents/                         # Ver Camada 3
```

### Middleware Stack (Ordem de Execução)

```
Requisição HTTP Entrante
        │
        ▼
┌──────────────────────────────────────────────┐
│ 1. CORSMiddleware                            │
│    Origens: ALLOWED_ORIGINS (.env)           │
│    Métodos: GET, POST, PUT, PATCH, DELETE    │
│    Credenciais: True                         │
├──────────────────────────────────────────────┤
│ 2. GZipMiddleware                            │
│    Comprime respostas > 1000 bytes           │
├──────────────────────────────────────────────┤
│ 3. Request Middleware (custom)               │
│    X-Request-ID: req_{timestamp_ms}         │
│    Structlog: bind method, path, request_id  │
│    Prometheus: REQUEST_COUNT + LATENCY       │
│    Response headers:                         │
│      X-Request-ID, X-Response-Time          │
│      X-Content-Type-Options: nosniff        │
│      X-Frame-Options: DENY                   │
│      X-XSS-Protection: 1; mode=block        │
│      Referrer-Policy: strict-origin...       │
│      Cross-Origin-Opener-Policy: same-origin │
│      Permissions-Policy: camera=(), ...     │
├──────────────────────────────────────────────┤
│ 4. JWT Dependency (por rota protegida)       │
│    Bearer token validation (HS256, 60min)    │
└──────────────────────────────────────────────┘
        │
        ▼
    Handler da Rota FastAPI
```

### Modelos de Dados Principais (SQLAlchemy ORM)

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│    User     │──▶│   Project   │──▶│    Scan     │──▶│   Finding   │
│─────────────│    │─────────────│    │─────────────│    │─────────────│
│ id (UUID)   │    │ id (UUID)   │    │ id (UUID)   │    │ id (UUID)   │
│ email       │    │ name        │    │ project_id  │    │ scan_id     │
│ hashed_pwd  │    │ description │    │ scan_type   │    │ title       │
│ role        │    │ owner_id    │    │ status      │    │ severity    │
│ is_active   │    │ scope       │    │ mode        │    │ cvss_score  │
│ created_at  │    │ targets     │    │ started_at  │    │ cwe         │
│             │    │ created_at  │    │ finished_at │    │ evidence    │
└─────────────┘    └─────────────┘    └─────────────┘    │ status      │
                                                          │ created_at  │
                                                          └─────────────┘

┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│    Asset    │    │  MobileApp  │    │ SecControl  │    │  AuditLog   │
│─────────────│    │─────────────│    │─────────────│    │─────────────│
│ domain      │    │ pkg_name    │    │ control_id  │    │ action      │
│ ip_addr     │    │ platform    │    │ name        │    │ user_id     │
│ open_ports  │    │ findings    │    │ status      │    │ resource    │
│ tech_stack  │    │ masvs_score │    │ result      │    │ timestamp   │
│ waf_type    │    │ pdf_report  │    │ evidence    │    │ ip_addr     │
│ cdn_type    │    │ created_at  │    │ created_at  │    │ request_id  │
└─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘
```

---

## 5. Camada 3 — Motor de Agentes Inteligentes (Celery + LLM)

### Orquestração dos Agentes

```
                 ┌──────────────────────────────────┐
                 │  ORCHESTRATOR (orchestrator.py)  │
                 │  Coordena o pipeline completo     │
                 │  de pentest autônomo              │
                 └─────────────────┬────────────────┘
                                   │
        ┌──────────────────────────┼──────────────────────────┐
        │                          │                          │
        ▼                          ▼                          ▼
┌───────────────┐        ┌─────────────────┐        ┌────────────────┐
│ Planner Agent │        │  Recon Agent    │        │ Crawler Agent  │
│ planner_agent │        │  recon_agent    │        │ crawler_agent  │
│               │        │                 │        │                │
│ • Lê o escopo │        │ • DNS-over-HTTPS│        │ • Spider URLs  │
│ • Gera plano  │        │ • CT Logs       │        │ • Form detect  │
│   de ataque   │        │ • WHOIS/ASN     │        │ • Link mapping │
│ • Prioriza    │        │ • Port probing  │        │ • JS parsing   │
│   targets     │        │ • WAF detect    │        │ • Auth forms   │
└───────────────┘        └─────────────────┘        └────────────────┘

┌───────────────┐        ┌─────────────────┐        ┌────────────────┐
│  Vuln Agent   │        │  Browser Agent  │        │Screenshot Agent│
│  vuln_agent   │        │  browser_agent  │        │screenshot_agent│
│               │        │                 │        │                │
│ • SQL Inj     │        │ • Playwright    │        │ • Full-page PNG│
│ • XSS         │        │ • JS rendering  │        │ • Visual diff  │
│ • SSRF        │        │ • SPA crawl     │        │ • Evidence kit │
│ • Auth bypass │        │ • Cookie abuse  │        │ • Timestamp    │
│ • IDOR/BOLA   │        │ • CSRF testing  │        │   watermark    │
└───────────────┘        └─────────────────┘        └────────────────┘

┌───────────────┐        ┌─────────────────┐
│   API Agent   │        │  Report Agent   │
│   api_agent   │        │  report_agent   │
│               │        │                 │
│ • REST probe  │        │ • Compila achados│
│ • GraphQL     │        │ • ReportLab PDF │
│ • Rate limit  │        │ • OpenPyXL xlsx │
│ • BOLA/BFLA   │        │ • SHA-256 hash  │
│ • Token bypass│        │ • Entrega final │
└───────────────┘        └─────────────────┘
```

### Filas Celery

| Fila | Workers | Tarefas Executadas |
|---|---|---|
| `default` | 4 | Dispatching genérico |
| `recon` | 2 | DNS, CT Logs, WHOIS, ASN |
| `crawler` | 2 | Spider, link mapping, form detection |
| `vuln` | 2 | SQLi, XSS, SSRF, auth bypass |
| `screenshot` | 1 | Playwright screenshots |
| `report` | 1 | Compilação de PDF/xlsx |

### Integração Multi-LLM

```
Backend → LLM Abstraction Layer (llm_provider via .env)
            │
            ├── Ollama  (localhost:11434 — llama3.2 — padrão self-hosted)
            ├── OpenAI  (GPT-4o via OPENAI_API_KEY)
            ├── Anthropic (Claude 3.5 via ANTHROPIC_API_KEY)
            └── Google  (Gemini 1.5 via GEMINI_API_KEY)

Uso dos LLMs:
  • hypothesis_engine.py → Geração de hipóteses de vetor de ataque
  • nl_planner.py        → Planejamento em linguagem natural
  • felipinho_service.py → Assistente AI conversacional
  • planner_agent.py     → Geração de plano tático de pentest
  • report_agent.py      → Narrativa executiva nos relatórios
```

---

## 6. Camada 4 — Scanner de Segurança Standalone

O `scanner/` é um **microserviço FastAPI autônomo** (independente do backend principal), especializado na execução direta das análises ofensivas:

### Módulos do Scanner

```
scanner/
├── main.py                        # FastAPI standalone (porta 8000 local)
│   Endpoints expostos:
│   POST /api/v1/osint/scan               → Varredura OSINT completa
│   POST /api/v1/security-controls/test   → Testar 1 controle específico
│   POST /api/v1/security-controls/test-all → Bateria dos 32 controles
│   POST /api/v1/security-controls/subdomain-enum → Enumerar subdomínios
│   POST /api/v1/security-controls/leak-scan → Scan de arquivos sensíveis
│   POST /api/v1/security-controls/report/pdf → PDF server-side (ReportLab)
│
├── osint_service.py               # Motor OSINT de perímetro
│   ├── DNS-over-HTTPS: 1.1.1.1/dns-query (Cloudflare)
│   │     Registros: A, AAAA, MX, TXT, NS, CAA, SOA
│   ├── crt.sh CT Logs API (subdomínios históricos e ativos)
│   ├── WHOIS/ASN lookup via IPinfo / RIPE NCC
│   ├── WAF fingerprinting via response headers:
│   │     cf-ray → Cloudflare
│   │     x-amz-cf-id → AWS CloudFront
│   │     AkamaiGHost → Akamai Intelligent Edge
│   ├── Security header completeness audit
│   ├── SPF/DMARC parser (análise anti-spoofing)
│   └── Google Dork Generator (env, git, sql, swagger, admin panels)
│
├── checks.py                      # 32 Controles de Segurança
│   Executados via asyncio.gather() em paralelo:
│   A — Transporte: TLS 1.3, HSTS, Certificate validity
│   B — Headers: CSP, X-Frame, nosniff, Referrer, Permissions
│   C — API Hardening: CORS wildcard, Rate Limit, TRACE/TRACK
│   D — Vazamento: .env, .git, .aws/credentials, backup.sql
│   E — Autenticação: Cookie flags, Session fixation, Brute-force
│   F — Integridade: SRI, CAA, DNSSEC, SPF, DMARC, SHA-256
│
├── mobile_report.py               # Motor Mobile Pentest
│   ANDROID (.apk):
│   ├── AndroidManifest.xml: debuggable, allowBackup, cleartext, exported
│   ├── Hardcoded secrets (regex): Google Key, AWS Key, Firebase, JWT, Stripe
│   ├── Weak crypto: MD5, SHA-1, AES/ECB (CWE-327/328)
│   ├── SSL Pinning: TrustAllCerts, checkValidity bypass (CWE-295)
│   └── Anti-reversing: Root detect, Frida hooks, Emulator detect
│   iOS (.ipa):
│   ├── Info.plist: NSAllowsArbitraryLoads, NSExceptionDomains
│   └── URL scheme conflicts e ATS violations
│   Score: OWASP MASVS v2.0 (7 domínios, 0-100, Level L1/L2)
│
├── security_controls_report.py    # ReportLab PDF multi-páginas (server-side)
├── report.py                      # Relatório técnico completo consolidado
├── report_xlsx.py                 # Planilha Excel de auditoria multi-abas
└── spider.py                      # Web spider e crawler de links
```

---

## 7. Camada 5 — Persistência (PostgreSQL + Redis)

### PostgreSQL 16

```
Banco: pentest (PostgreSQL 16-alpine)
Conexão async: asyncpg + SQLAlchemy 2.0
Conexão sync:  psycopg2 (Alembic migrations)

Tabelas principais:
┌──────────────────┬──────────────────────────────────────────────────┐
│ Tabela           │ Propósito                                        │
├──────────────────┼──────────────────────────────────────────────────┤
│ users            │ Operadores com roles: admin/analyst/viewer       │
│ projects         │ Escopos de pentest e metadados de cliente        │
│ scans            │ Jobs com status: pending/running/done/failed     │
│ findings         │ Vulnerabilidades: CVSS, CWE, evidência, status   │
│ assets           │ Domínios, IPs, portas, tech stack, WAF/CDN       │
│ mobile_apps      │ Binários analisados + resultados MASVS + PDF     │
│ security_controls│ Status de cada controle por alvo e por scan      │
│ reports          │ Metadados de relatórios gerados (path, hash)     │
│ audit_logs       │ Trilha imutável: action, user, IP, timestamp     │
│ approvals        │ Aprovações para scans em modo AUTHORIZED         │
│ evidence         │ Screenshots, HAR, texto — ligados a findings     │
└──────────────────┴──────────────────────────────────────────────────┘
```

### Redis 7

```
Configuração: maxmemory 512MB, allkeys-lru, password auth

Namespaces de chaves:
┌──────────────────────────────┬──────────────────────────────────────────┐
│ Prefixo de Chave             │ Uso                                      │
├──────────────────────────────┼──────────────────────────────────────────┤
│ celery:*                     │ Filas e resultados de tarefas Celery     │
│ dns_cache:{domain}:{type}    │ Cache DNS (TTL 1h — evita throttling)    │
│ osint:{target}:{ts}          │ Cache resultados OSINT (TTL 1h)          │
│ rl:{endpoint}:{ip}           │ Rate Limiting por endpoint e por IP      │
│ session:{user_id}:{jti}      │ Blacklist de tokens revogados            │
│ scan_result:{scan_id}        │ Buffer de resultados de scan em progresso│
└──────────────────────────────┴──────────────────────────────────────────┘
```

---

## 8. Camada 6 — Observabilidade (Prometheus + Grafana + Flower)

```
Prometheus → http://localhost:9090
  Scrape: /metrics a cada 15s

Métricas customizadas (app/main.py + app/core/metrics.py):

  api_requests_total{method, endpoint, status}    → Counter
  api_request_duration_seconds{method, endpoint} → Histogram (p50, p95, p99)
  findings_total{severity}                        → Counter (critical, high, medium, low)
  screenshots_total                               → Counter
  reports_generated{report_type}                  → Counter (pdf, xlsx)
  pentest_jobs_total                              → Counter
  pentest_jobs_running                            → Gauge

Grafana → http://localhost:3001 (admin / changeme_grafana)
  Dashboards provisionados: /docker/grafana/provisioning/
  DataSource: Prometheus

Flower → http://localhost:5555
  Monitor de tarefas Celery em tempo real
  Filas, workers ativos, histórico, retries
```

---

## 9. Camada 7 — Ambiente de Laboratório Isolado

```
Docker Network: pentest-lab (bridge interno, sem rota para internet)

OWASP Juice Shop → http://localhost:3002
Container: bkimminich/juice-shop:latest
Alias interno DNS: juiceshop

Usado para:
  • Testes de agentes autônomos sem risco real
  • Validação de payloads: SQLi, XSS, SSRF, IDOR, BOLA
  • Treino e calibração do Vuln Agent
  • Demonstrações controladas em auditorias corporativas

Acesso de rede:
  pentest-worker → pentest-net + pentest-lab (ambas as redes)
  pentest-beat   → pentest-net apenas
  Demais serviços → pentest-net apenas
```

---

## 10. Fluxo de Dados — Autenticação Zero-Trust

```
Usuário abre o navegador
       │
       ▼
GET /login → Next.js renderiza login/page.tsx
       │
       ├── MODO A: Credenciais + 2FA TOTP
       │    │
       │    │ 1. Preenche: email, senha, 6 dígitos TOTP
       │    │    (6 inputs individuais com auto-focus + paste support)
       │    │
       │    │ 2. Validação client-side:
       │    │    email.includes('@') ✓
       │    │    password.length >= 6 ✓
       │    │    totpCode.join('').length === 6 ✓
       │    │
       │    ▼
       │   POST /api/v1/auth/login → FastAPI
       │    │
       │    │ 3. bcrypt.verify(password, hashed_pwd) ✓
       │    │ 4. TOTP.verify(code, ±30s window) ✓
       │    │ 5. Gera JWT HS256 (exp: 60min)
       │    │ 6. Registra em audit_logs (action: LOGIN)
       │    │
       │    ▼
       │   Next.js → js-cookie.set('token') → router.push('/dashboard')
       │
       └── MODO B: QR Code 2D Mobile
            │
            │ 1. qrcode lib gera matriz 2D (ECC Level M)
            │    Payload selecionável:
            │    - URL: https://morfeusec.local/auth/verify?session=...&pin=...
            │    - TOTP: otpauth://totp/morfeusec%20OSINT:user@...?secret=...
            │
            │ 2. Smartphone lê QR (câmera nativa iOS, Google Lens, WhatsApp, Authy)
            │    Temporizador: 60 segundos de expiração visual
            │
            │ 3. Usuário digita PIN de 6 dígitos no campo de confirmação
            │    Botão bloqueado: disabled={pin.length < 6 || timeLeft === 0}
            │
            │ 4. Validação biométrica simulada com loading + feedback visual
            │
            ▼
           authApi.login() → JWT → router.push('/dashboard')
```

---

## 11. Fluxo de Dados — Varredura OSINT Completa

```
Operador acessa /osint
       │
       │ 1. Insere domínio alvo (ex: empresa.com.br)
       │ 2. Seleciona módulos: DNS, Certs, WAF/Headers, S3, SPF/DMARC, Dorks
       │
       ▼
POST /api/v1/osint/scan (JSON: { target, modules })
       │
       ▼
FastAPI → scope_validator.py
       │ Verifica se domínio está no escopo autorizado do projeto
       │ Erro 403 se fora do escopo
       │
       ▼
osint_service.py → executa módulos selecionados em paralelo:

  DNS-over-HTTPS (Cloudflare 1.1.1.1/dns-query)
  ├── A records → IPs do domínio e subdomínios
  ├── AAAA records → IPv6
  ├── MX records → servidores de e-mail
  ├── TXT records → SPF, DMARC, Google verification, etc.
  ├── NS records → nameservers
  ├── CAA records → autoridades de emissão de certificados
  └── SOA records → zona de autoridade

  crt.sh Certificate Transparency
  └── SELECT name_value FROM certificates WHERE common_name LIKE '%target%'
      → subdomínios históricos e ativos (certificados emitidos)

  HTTPX → HEAD {target} → response headers fingerprint
  ├── cf-ray      → Cloudflare CDN/WAF
  ├── x-amz-cf-id → AWS CloudFront
  ├── AkamaiGHost → Akamai Intelligent Edge
  ├── HSTS        → max-age, includeSubDomains, preload
  ├── CSP         → Content-Security-Policy completeness
  └── X-Frame, nosniff, Referrer, Permissions-Policy

  SPF/DMARC Parser (via DNS TXT)
  ├── SPF:   v=spf1 ... -all → PASS | ~all → WARN | ?all → FAIL
  └── DMARC: p=reject → PASS | p=quarantine → WARN | p=none → FAIL

  Google Dork Generator
  └── site:{target} (filetype:env | filetype:git | intitle:"Index of")
      site:{target} (filetype:sql | inurl:admin | intitle:swagger)

       │
       ▼
Resultados → PostgreSQL (assets table) + Redis cache (TTL 1h)
       │
       ▼
FastAPI → JSON response → Next.js renderiza por categoria
       │
       └── "Exportar Laudo PDF" → pdf-lib gera binário no browser
```

---

## 12. Fluxo de Dados — Mobile Pentest APK/IPA

```
Operador acessa /mobile-pentest
       │
       │ 1. Drag-and-drop de múltiplos .apk e/ou .ipa
       │ 2. Configuração: platform, target package, modo de análise
       │
       ▼
POST /api/v1/mobile/upload (multipart/form-data)
       │
       ▼
mobile_pentest_service.py → análise por plataforma:

  ANDROID (.apk):
  ├── zipfile.extractall() → descompacta binário
  ├── lxml.parse('AndroidManifest.xml')
  │     android:debuggable="true"            → CRITICAL
  │     android:allowBackup="true"           → HIGH
  │     android:usesCleartextTraffic="true"  → HIGH
  │     exported="true" sem permission       → HIGH
  │     Deep link intent sem validação       → MEDIUM
  │
  ├── Hardcoded secrets (regex scan em .smali/.dex/.java)
  │     r'AIza[0-9A-Za-z\-_]{35}'           → Google API Key → CRITICAL
  │     r'AKIA[0-9A-Z]{16}'                 → AWS Access Key → CRITICAL
  │     r'https://.*\.firebaseio\.com'       → Firebase URL → HIGH
  │     r'eyJ[A-Za-z0-9-_]+\.'              → JWT token → HIGH
  │     r'sk_live_[0-9a-zA-Z]{24}'          → Stripe Key → CRITICAL
  │
  ├── Weak crypto detection
  │     "MD5"    usage → MEDIUM (CWE-327)
  │     "SHA-1"  usage → MEDIUM (CWE-328)
  │     "AES/ECB" mode → HIGH   (CWE-327)
  │
  └── SSL Pinning + Anti-reversing
        TrustAllCerts implementation → CRITICAL (CWE-295)
        checkValidity() returning true → CRITICAL
        Root detection absent          → HIGH
        Frida hook detection absent    → HIGH
        Emulator detection absent      → MEDIUM

  iOS (.ipa):
  ├── plistlib.load('Info.plist')
  │     NSAllowsArbitraryLoads: true → CRITICAL (ATS disabled)
  │     NSExceptionDomains entries   → MEDIUM (per-domain exceptions)
  │     LSApplicationQueriesSchemes  → LOW (URL scheme exposure)
  └── Binary entitlements audit

       │
       ▼
OWASP MASVS v2.0 Scoring (7 domínios):
  MASVS-STORAGE:     Armazenamento seguro e proteção de dados
  MASVS-CRYPTO:      Criptografia forte e adequada
  MASVS-AUTH:        Autenticação robusta e gestão de sessão
  MASVS-NETWORK:     Segurança de comunicação de rede
  MASVS-PLATFORM:    Interação segura com a plataforma OS
  MASVS-CODE:        Qualidade e proteção do código-fonte
  MASVS-RESILIENCE:  Resiliência contra engenharia reversa

  Score final: 0–100
  Level L1: Segurança básica de mercado (todos apps)
  Level L2: Segurança estendida (apps com dados sensíveis)

       │
       ▼
Salvar → PostgreSQL (mobile_apps + findings)
PDF Client → pdf-lib (MASVS report)
Excel → OpenPyXL (planilha de auditoria .xlsx)
```

---

## 13. Fluxo de Dados — 32 Controles de Segurança BACEN

```
Operador acessa /security-controls
       │
       │ 1. Insere URL alvo (ex: https://banco.com.br)
       │ 2. Seleciona: controle único ou bateria completa
       │
       ▼
POST /api/v1/security-controls/test-all
       │
       ▼
checks.py → asyncio.gather(*[check_01(), check_02(), ..., check_32()])

CATEGORIA A — Segurança de Transporte:
  [C01] TLS 1.3 enforcement — verifica handshake, cipher suite, ECDHE
  [C02] TLS 1.0/1.1 desativado — POODLE/BEAST prevention
  [C03] HSTS max-age >= 31536000 (1 ano)
  [C04] HSTS includeSubDomains + preload
  [C05] Certificado válido, CN match, não expirado

CATEGORIA B — Hardening de Headers HTTP:
  [C06] Content-Security-Policy — presente e configurado
  [C07] X-Frame-Options: DENY ou SAMEORIGIN
  [C08] X-Content-Type-Options: nosniff
  [C09] Referrer-Policy: strict-origin-when-cross-origin
  [C10] Permissions-Policy: camera=(), microphone=(), ...
  [C11] Cross-Origin-Resource-Policy configurado

CATEGORIA C — API e Web Hardening:
  [C12] CORS: Access-Control-Allow-Origin != '*'
  [C13] Rate Limiting: X-RateLimit-Limit headers presentes
  [C14] HTTP TRACE/TRACK desativados
  [C15] Server header suprimido ou genérico
  [C16] X-Powered-By removido

CATEGORIA D — Exposição de Ativos Críticos:
  [C17] GET /.env → não retorna HTTP 200 (CRITICAL se sim)
  [C18] GET /.git/config → não exposto
  [C19] GET /.aws/credentials → não acessível
  [C20] GET /backup.sql → não exposto
  [C21] GET /phpinfo.php → não exposto
  [C22] GET /wp-config.php → não exposto

CATEGORIA E — Autenticação e Sessão:
  [C23] Cookies: Secure + HttpOnly + SameSite=Strict
  [C24] Session fixation prevention
  [C25] Login endpoint sem rate limiting → brute-force risk

CATEGORIA F — Monitoramento e Integridade:
  [C26] Subresource Integrity (SRI) em scripts externos
  [C27] DNS CAA record configurado (restrict cert issuance)
  [C28] DNSSEC habilitado na zona
  [C29] SPF record com -all (rejeição explícita)
  [C30] DMARC p=reject (proteção contra spoofing)
  [C31] MX records suportam STARTTLS / SMTPS (465/587)
  [C32] Assinatura SHA-256 do relatório de auditoria gerado

       │
       ▼
Resultado → PostgreSQL (security_controls) + Redis cache
       │
       └── "Exportar Laudo PDF" → pdf-lib (client) ou ReportLab (server fallback)
```

---

## 14. Fluxo de Dados — Geração de Laudos em PDF

```
Operador clica "Exportar Laudo PDF"
       │
       ▼
ESTRATÉGIA 1 (Primária) — Client-Side com pdf-lib:
       │
       │ src/lib/pdf-lib-security-controls.ts
       │ OU
       │ src/lib/pdf-lib-mobile.ts
       │
       │ 1. PDFDocument.create()
       │ 2. Adiciona 3 páginas:
       │    CAPA:    Logo morfeusec + data + operador + alvo + SHA-256
       │    SUMÁRIO: Score geral, postura de risco, highlights, CVSS
       │    DETALHE: Tabela de controles, evidências, recomendações
       │ 3. Assina hash SHA-256 do conteúdo dos dados de scan
       │ 4. pdfDoc.save() → Uint8Array (binário)
       │ 5. new Blob([bytes], { type: 'application/pdf' })
       │ 6. URL.createObjectURL(blob)
       │ 7. a.download = '32-controles-bacen-2026-09-05.pdf'
       │ 8. a.click() → download direto SEM nova aba em branco
       │
       ▼ (se pdf-lib falhar ou timeout)

ESTRATÉGIA 2 (Fallback) — Server-Side com ReportLab:
       │
       │ POST /api/v1/security-controls/report/pdf
       │    → security_controls_report.py
       │    → ReportLab: multi-página, estilos corporativos
       │    → response: application/pdf stream
       │
       │ Frontend:
       │   const blob = await response.blob()
       │   const url = URL.createObjectURL(blob)
       │   a.download = 'laudo.pdf'; a.click()
       │
       ▼

CONTEÚDO DOS LAUDOS PDF:
  Capa:         Logo morfeusec, timestamp, operador, alvo, hash SHA-256
  Sumário Exec: Score geral, postura (Alto/Médio/Baixo Risco), highlights
  Conformidade: Tabela Pass/Fail/Warn por controle com evidência
  Matriz Risco: Mapa de calor por categoria e severidade
  Técnico:      Detalhe de cada falha: CWE, CVSS, PoC, recomendação
  Auditoria:    Timestamp UTC, operador, session ID, request hash
```

---

## 15. Rede Docker e Mapeamento de Portas

```
Serviço              Host                  Container              Rede
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
frontend             0.0.0.0:3000      →  pentest-frontend:3000   pentest-net
frontend (manual)    0.0.0.0:3005      →  (next start -p 3005)    —
backend/scanner      0.0.0.0:8000      →  pentest-backend:8000    pentest-net
postgres             interno           →  pentest-postgres:5432   pentest-net
redis                interno           →  pentest-redis:6379      pentest-net
prometheus           127.0.0.1:9090    →  pentest-prometheus:9090 pentest-net
grafana              127.0.0.1:3001    →  pentest-grafana:3000    pentest-net
juiceshop            127.0.0.1:3002    →  pentest-juiceshop:3000  pentest-lab
flower               127.0.0.1:5555    →  pentest-flower:5555     pentest-net

Redes Docker:
  pentest-net  → bridge (acesso externo às portas publicadas)
  pentest-lab  → bridge internal (totalmente isolado da internet)

Workers Celery — acesso dual:
  pentest-worker → pentest-net + pentest-lab
  pentest-beat   → pentest-net apenas
```

---

## 16. Segurança e Controles de Acesso

| Controle | Implementação |
|---|---|
| **Hashing de Senhas** | bcrypt com salt automático via passlib (cost factor 12) |
| **Tokens de Sessão** | JWT HS256, TTL 60min, revogação por Redis blacklist |
| **2FA TOTP** | RFC 6238 compatível com Google/Microsoft Authenticator |
| **QR Code 2FA** | qrcode (ECC-M), otpauth://totp URI ou URL de sessão dinâmica |
| **Expiração de QR** | 60 segundos com countdown visual e bloqueio de botão |
| **Validação de Escopo** | scope_validator.py — todo target validado antes de execução |
| **Kill Switch** | kill_switch.py — interrupção imediata de todos os agentes ativos |
| **Audit Log** | Trilha imutável com action, user_id, IP, request_id, timestamp |
| **CORS** | Lista explícita via ALLOWED_ORIGINS — sem wildcards |
| **Rate Limiting** | Redis-backed por endpoint e por IP (X-RateLimit-* headers) |
| **Security Headers** | nosniff, DENY, XSS-block, COOP, Referrer, Permissions-Policy |
| **GZip** | Compressão de respostas > 1 KB (GZipMiddleware) |
| **Structured Logging** | Structlog JSON correlacionado por X-Request-ID |
| **Scope Enforcement** | Modo PASSIVE/SAFE_ACTIVE/AUTHORIZED_ADVERSARY |

---

## 17. Tabela de Tecnologias Completa

### Frontend

| Tecnologia | Versão | Categoria | Uso |
|---|---|---|---|
| Next.js | 14.2.13 | Framework | SSR/SSG + App Router + Route Groups |
| React | 18.3.1 | UI Library | Componentes reativos + hooks |
| TypeScript | 5.6.2 | Linguagem | Tipagem estática end-to-end |
| Tailwind CSS | 3.4.12 | Estilização | Utilitários + tema Dark Cyber |
| pdf-lib | 1.17.1 | PDF Engine | Geração binária de PDF vetorial no cliente |
| qrcode | 1.5.4 | QR Generator | Matriz 2D ECC-M — iOS/Android/2FA Apps |
| Recharts | 2.12.7 | Gráficos | Radar, barras, rosca, área temporal |
| D3 | 7.9.0 | Visualização | Grafo interativo de superfície de ataque |
| Lucide React | 0.441.0 | Ícones | SVG vetoriais de segurança |
| Axios | 1.7.7 | HTTP Client | Requisições + interceptadores JWT |
| TanStack Query | 5.56.2 | State | Cache + refetch + estado de queries |
| React Hot Toast | 2.4.1 | UI | Notificações de scan e autenticação |
| Framer Motion | 11.5.4 | Animação | Transições + microinterações |
| date-fns | 3.6.0 | Utilitário | Formatação de datas |
| js-cookie | 3.0.5 | Sessão | Armazenamento de token JWT |
| Zod | 3.23.8 | Validação | Schemas de formulários e API |
| react-hook-form | 7.53.0 | Formulários | Formulários controlados tipados |
| clsx | 2.1.1 | CSS | Composição condicional de classes |
| prismjs | 1.29.0 | Code | Highlight de evidências técnicas |

### Backend e Scanners

| Tecnologia | Versão | Categoria | Uso |
|---|---|---|---|
| Python | 3.11+ | Linguagem | Core de análise e automação |
| FastAPI | 0.115.0 | Framework | API REST assíncrona de alta performance |
| Uvicorn | 0.30.6 | Servidor | ASGI server de produção |
| SQLAlchemy | 2.0.35 | ORM | Mapeamento objeto-relacional async |
| asyncpg | 0.29.0 | DB Driver | Driver PostgreSQL nativo async |
| psycopg2-binary | 2.9.9 | DB Driver | Driver PostgreSQL sync (Alembic) |
| Alembic | 1.13.3 | Migrations | Versionamento de schema do banco |
| Celery | 5.4.0 | Tasks | Fila de tarefas distribuídas |
| Flower | 2.0.1 | Monitor | Dashboard de tasks Celery |
| Pydantic | 2.9.2 | Validação | Schemas e serialização de dados |
| pydantic-settings | 2.5.2 | Config | Configuração tipada via .env |
| python-jose | 3.3.0 | Auth | Geração e validação de JWT |
| passlib[bcrypt] | 1.7.4 | Auth | Hashing seguro de senhas |
| HTTPX | 0.27.2 | HTTP | Cliente HTTP async para probers |
| aiohttp | 3.10.5 | HTTP | Requisições HTTP assíncronas |
| dnspython | 2.6.1 | DNS | Consultas DNS programáticas |
| Playwright | 1.47.0 | Browser | Automação de browser para DAST |
| WeasyPrint | 62.3 | PDF | PDF via HTML/CSS (alternativo) |
| Jinja2 | 3.1.4 | Templates | Templates de relatórios HTML |
| ReportLab | 4.2.2 | PDF | Geração de PDF server-side |
| OpenPyXL | (fpdf2) | Excel | Planilhas .xlsx de auditoria |
| Prometheus Client | 0.21.0 | Metrics | Exposição de métricas /metrics |
| Structlog | 24.4.0 | Logging | Logging estruturado JSON |
| cryptography | 43.0.1 | Crypto | Operações criptográficas |
| tldextract | 5.1.2 | Parsing | Extração de TLD de domínios |
| netaddr | 1.3.0 | Rede | Parsing de IPs e CIDRs |
| OpenAI | 1.47.0 | LLM | Integração GPT-4o |
| Anthropic | 0.34.2 | LLM | Integração Claude 3.5 |
| google-generativeai | 0.8.1 | LLM | Integração Gemini 1.5 |
| ollama | 0.3.3 | LLM | Self-hosted llama3.2 local |
| BeautifulSoup4 | 4.12.3 | Parsing | Parse HTML de respostas |
| lxml | 5.3.0 | Parsing | Parse XML/HTML (AndroidManifest) |
| Pillow | 10.4.0 | Imagens | Processamento de screenshots |
| websockets | 13.0.1 | WebSocket | Comunicação em tempo real |
| pytest | 8.3.3 | Testes | Suite de testes (47 testes) |
| pytest-asyncio | 0.24.0 | Testes | Testes assíncronos |

### Infraestrutura

| Tecnologia | Versão | Função |
|---|---|---|
| Docker | 24+ | Containerização de todos os serviços |
| Docker Compose | 2.20+ | Orquestração local multi-container |
| PostgreSQL | 16-alpine | Banco de dados relacional principal |
| Redis | 7-alpine | Cache, fila Celery e rate limiting |
| Prometheus | Latest | Coleta e armazenamento de métricas |
| Grafana | Latest | Dashboards de observabilidade |
| OWASP Juice Shop | Latest | Target de laboratório isolado |

---

<div align="center">

**morfeusec OSINT** © 2026 — Felipe Costa · felipe_c@myyahoo.com

*Arquitetura de 7 camadas • 30+ serviços • 60+ tecnologias*

</div>
"""

with open('ARCHITECTURE.md', 'w', encoding='utf-8') as f:
    f.write(content)

print("ARCHITECTURE.md gerado com sucesso!")
print(f"Tamanho: {len(content)} caracteres")
