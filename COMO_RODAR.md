# Setup Rápido — AI Pentest Platform (Frontend Estático)

## Pré-requisito único: Node.js

**Instale Node.js LTS:**
https://nodejs.org/en/download — baixe o instalador Windows (.msi) e execute.

Após instalar, **feche e reabra o terminal**.

---

## Rodar em 3 comandos

```powershell
cd C:\Users\loren\Documents\code_felipe\pentest\frontend

npm install

npm run dev
```

Acesse: **http://localhost:3000**

Login: qualquer email + qualquer senha (dados estáticos, sem backend)

---

## Estrutura de dados

Os dados ficam em `public/data/`:

| Arquivo | Conteúdo |
|---------|----------|
| `projects.json` | 4 projetos de pentest |
| `findings.json` | 14 findings com OWASP/CWE/CVSS |
| `assets.json` | 7 assets descobertos |
| `scans.json` | 3 scans com status/progresso |
| `audit_logs.json` | 14 entradas de auditoria |

Para adicionar dados: **edite os arquivos JSON diretamente** e recarregue o browser.

---

## Páginas disponíveis

| Página | URL |
|---|---|
| Dashboard | http://localhost:3000/dashboard |
| Scanner | http://localhost:3000/scan |
| Controles de Segurança | http://localhost:3000/security-controls |
| OSINT Recon | http://localhost:3000/osint |
| Reports | http://localhost:3000/reports |
| Projetos | http://localhost:3000/projects |
| Projeto Detalhe | http://localhost:3000/projects/proj-001 |
| Findings | http://localhost:3000/findings |
| Attack Surface | http://localhost:3000/attack-surface |
| Audit Logs | http://localhost:3000/audit-logs |

---

## Adicionar um novo projeto

1. Abra `public/data/projects.json`
2. Adicione um objeto no array seguindo o mesmo padrão
3. Adicione findings em `public/data/findings.json` com `project_id` igual ao novo ID
4. Salve — o browser atualiza automaticamente (hot reload)

