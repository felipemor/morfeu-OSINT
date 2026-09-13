# 🚀 Guia de Execução & Implantação (Local, Docker, AWS, GCP, Azure & DevOps)

Este documento contém o guia completo para rodar a plataforma **morfeusec OSINT (AI Autonomous Pentest Platform)** em qualquer ambiente: localmente no Windows com **1-Clique**, em **Containers Docker**, em nuvens públicas (**AWS, GCP, Azure**) e em **Esteiras de CI/CD DevOps**.

---

## 💻 1. Execução Local em 1-Clique (Windows)

Para iniciar toda a plataforma (Frontend Next.js + Backend Scanner Python API) e abrir o navegador automaticamente:

1. **Dê um duplo clique no arquivo [`RODAR_TUDO.bat`](file:///c:/Users/loren/Documents/code_felipe/pentest/RODAR_TUDO.bat)** (ou execute via terminal):

```cmd
.\RODAR_TUDO.bat
```

> **O que o script faz automaticamente:**
> - Checa se o Node.js e Python estão instalados.
> - Instala os pacotes do `frontend` (`npm install`) e cria o ambiente virtual Python (`.venv`) do `scanner`.
> - Inicia a API do Backend/Scanner na porta `http://localhost:8000`.
> - Inicia a UI do Frontend Next.js na porta `http://localhost:3000`.
> - **Abre o navegador automaticamente** em `http://localhost:3000`.

---

## 🐳 2. Execução via Containers (Docker & Docker Compose)

A plataforma conta com uma pilha completa conteinerizada em [`docker-compose.yml`](file:///c:/Users/loren/Documents/code_felipe/pentest/docker-compose.yml) contendo **PostgreSQL, Redis, Backend FastAPI, Frontend Next.js, Grafana e Prometheus**.

### Passo a passo para rodar no Docker:

1. Certifique-se de que o **Docker Desktop** está rodando.
2. Na raiz do projeto, execute:

```bash
# Subir toda a infraestrutura em background
docker compose up -d --build
```

3. Verifique os logs e o status dos serviços:

```bash
docker compose ps
docker compose logs -f backend
```

4. **Acesse:**
   - **Frontend UI:** `http://localhost:3000`
   - **Backend API (Swagger Docs):** `http://localhost:8000/docs`
   - **Grafana Analytics:** `http://localhost:3001` (login: `admin` / `admin`)

---

## ☁️ 3. Implantação na Nuvem AWS (Amazon Web Services)

### Opção A: AWS App Runner / Elastic Container Service (ECS Fargate) — Recomendações Serverless
1. **Publicar imagem no AWS ECR (Elastic Container Registry):**
   ```bash
   aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin <AWS_ACCOUNT_ID>.dkr.ecr.us-east-1.amazonaws.com

   # Build e Tag
   docker build -t morfeusec-backend ./backend
   docker tag morfeusec-backend:latest <AWS_ACCOUNT_ID>.dkr.ecr.us-east-1.amazonaws.com/morfeusec-backend:latest
   docker push <AWS_ACCOUNT_ID>.dkr.ecr.us-east-1.amazonaws.com/morfeusec-backend:latest
   ```

2. **Criar o serviço no AWS App Runner:**
   - Vá ao console da AWS ➔ **App Runner** ➔ **Create Service**.
   - Escolha o repositório ECR da imagem `morfeusec-backend:latest`.
   - Defina a porta de escuta para `8000`.
   - Adicione as variáveis de ambiente (`DATABASE_URL`, `SECRET_KEY`, etc.).

### Opção B: AWS EC2 ou Lightsail (Instância VM)
1. Crie uma instância EC2 (Ubuntu 22.04 LTS, t3.medium recomendado).
2. Libere as portas de Inbound `80`, `443`, `3000` e `8000` no **Security Group**.
3. Na VM, instale Docker e Git:
   ```bash
   sudo apt update && sudo apt install -y docker.io docker-compose git
   git clone https://github.com/felipemor/morfeu-OSINT.git
   cd morfeu-OSINT
   docker compose up -d --build
   ```

---

## ☁️ 4. Implantação na Nuvem GCP (Google Cloud Platform)

### Opção A: GCP Cloud Run (Serverless Container)
1. **Autenticar e subir a imagem para o GCP Artifact Registry:**
   ```bash
   gcloud auth configure-docker us-central1-docker.pkg.dev

   # Build e Tag
   docker build -t us-central1-docker.pkg.dev/[PROJECT_ID]/morfeusec/backend:latest ./backend
   docker push us-central1-docker.pkg.dev/[PROJECT_ID]/morfeusec/backend:latest
   ```

2. **Implantar no Cloud Run:**
   ```bash
   gcloud run deploy morfeusec-backend \
     --image=us-central1-docker.pkg.dev/[PROJECT_ID]/morfeusec/backend:latest \
     --platform=managed \
     --region=us-central1 \
     --allow-unauthenticated \
     --port=8000
   ```

### Opção B: GCP Compute Engine (GCE)
1. Crie uma VM Compute Engine com imagem Container-Optimized OS ou Ubuntu.
2. Clone o repositório e suba com Docker Compose da mesma forma descrita acima.

---

## ☁️ 5. Implantação na Nuvem Azure

### Opção A: Azure Container Apps / ACR (Azure Container Registry)
1. **Publicar a imagem no ACR:**
   ```bash
   az acr login --name <REGISTRY_NAME>
   docker build -t <REGISTRY_NAME>.azurecr.io/morfeusec-backend:latest ./backend
   docker push <REGISTRY_NAME>.azurecr.io/morfeusec-backend:latest
   ```

2. **Deploy no Azure Container Apps:**
   ```bash
   az containerapp create \
     --name morfeusec-backend \
     --resource-group rg-pentest \
     --environment env-pentest \
     --image <REGISTRY_NAME>.azurecr.io/morfeusec-backend:latest \
     --target-port 8000 \
     --ingress external
   ```

---

## 🔄 6. Esteira CI/CD DevOps (Automação Contínua)

O repositório já inclui a esteira completa configurada em [`.github/workflows/deploy.yml`](file:///c:/Users/loren/Documents/code_felipe/pentest/.github/workflows/deploy.yml).

### Como funciona o Pipeline CI/CD:
1. **Etapa 1 — Lint & Typecheck (`lint-and-test`):**
   - Executa a verificação estática de tipos no Next.js (`npx tsc --noEmit`).
   - Valida a compilação do Backend Python (`py_compile`).
2. **Etapa 2 — Docker Build & Push (`build-and-push-docker`):**
   - Constrói as imagens Docker de produção do Backend e Frontend em paralelo.
   - Publica automaticamente as imagens com a tag `:latest` e `:sha`.
3. **Etapa 3 — Deploy Automático na Nuvem (`deploy-aws-gcp`):**
   - Dispara a atualização de serviço no AWS App Runner / GCP Cloud Run.

---

## 📌 7. Tabela de Módulos e Rotas da Aplicação

| Módulo / Página | Rota URL | Função e Cobertura de Segurança |
|---|---|---|
| **Dashboard Executivo** | `http://localhost:3000/dashboard` | Health Score (0-100), Tendência 12M & Métricas CISO |
| **Governança Tri-Pilar** | `http://localhost:3000/executive-governance` | Matriz Tri-Pilar de Riscos Corporativos |
| **Scanner Multi-URLs** | `http://localhost:3000/scan` | Varredura DAST/SAST Automatizada & Reativa |
| **Central de Findings** | `http://localhost:3000/findings` | Gestão Unificada de Vulnerabilidades |
| **Guia de Remediação** | `http://localhost:3000/remediation` | SOPs e Playbooks de Correção com Código Pronto |
| **Evidence Vault SHA-256** | `http://localhost:3000/evidence-vault` | Cofre de Provas Técnicas com Hash Tamper-Evident |
| **Correlation & Risco** | `http://localhost:3000/correlation` | Grafo de Impacto em Ativos & Aceite de Risco |
| **Mobile Pentest (APK/iOS)**| `http://localhost:3000/mobile-pentest` | Análise SAST/DAST OWASP MASVS v2.0 |
| **OSINT Intelligence** | `http://localhost:3000/osint` | Reconhecimento Perimétrico, DNS e WHOIS |
| **Controles BACEN 4.893** | `http://localhost:3000/security-controls` | Auditoria dos 32 Controles Regulatórios |
| **AppSec / ASPM Posture** | `http://localhost:3000/aspm` | Postura de Código, Checkmarx e Quality Gates |
| **Microsegmentação Híbrida**| `http://localhost:3000/microsegmentation` | Visualização de Fluxos Leste-Oeste & Zero Trust |
| **Morfeu XDR** | `http://localhost:3000/morfeuxdr` | Telemetria e Detecção de Ameaças em Tempo Real |
| **Audit Logs** | `http://localhost:3000/audit-logs` | Trilha de Auditoria com Assinatura Criptográfica |

---

## 🎹 8. Atalhos Globais

- **Busca Global**: Pressione `Ctrl + K` em qualquer tela para abrir o Command Palette.
- **Security Copilot (IA)**: Clique em `Security Copilot (IA)` na barra lateral para acionar a inteligência artificial.
