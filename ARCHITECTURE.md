# MEGA PROMPT — EVOLUÇÃO DA AI AUTONOMOUS PENTEST PLATFORM

## Novo módulo: HYBRID MICROSEGMENTATION & ZERO TRUST

Você é um **Principal Software Architect, Senior Cybersecurity Engineer, Cloud Security Architect, DevSecOps Engineer, Product Designer e AI Engineer**, responsável por evoluir uma plataforma empresarial existente de **AI Autonomous Pentest**.

Sua missão é **não criar uma aplicação isolada**.

Você deverá:

> **INSPECIONAR A APLICAÇÃO EXISTENTE, ENTENDER SUA ARQUITETURA, PRESERVAR TODAS AS FUNCIONALIDADES ATUAIS E IMPLEMENTAR UMA NOVA ABA/MÓDULO NATIVO DE MICROSEGMENTAÇÃO HÍBRIDA.**

O novo módulo deverá elevar a plataforma de um simples sistema de Auto Pentest para uma plataforma integrada de:

**DISCOVERY → ATTACK PATH → VALIDATION → LATERAL MOVEMENT → MICROSEGMENTATION → POLICY → CONTINUOUS VALIDATION**

O objetivo é criar uma experiência de segurança comparável, conceitualmente, às plataformas corporativas modernas de microsegmentação, com forte inspiração funcional em soluções como Akamai Guardicore, Illumio e plataformas de observabilidade de rede, porém utilizando prioritariamente tecnologias open source.

---

# 1. REGRA MAIS IMPORTANTE

Antes de escrever qualquer código:

1. Analise completamente o projeto existente.
2. Identifique:

   * frontend;
   * backend;
   * banco de dados;
   * autenticação;
   * autorização;
   * estrutura de rotas;
   * componentes reutilizáveis;
   * design system;
   * APIs existentes;
   * modelos de dados;
   * filas/workers;
   * Docker;
   * variáveis de ambiente;
   * configurações;
   * integrações;
   * logging;
   * testes;
   * CI/CD.
3. Não substitua arquitetura existente sem necessidade.
4. Não duplique funcionalidades.
5. Reutilize componentes existentes.
6. Preserve compatibilidade com todas as funcionalidades atuais.
7. A nova funcionalidade deve parecer que sempre fez parte da aplicação.
8. Não crie mockups desconectados do backend.
9. Não implemente apenas telas estáticas.
10. Tudo que aparecer na interface deve possuir uma fonte de dados real ou uma camada de abstração claramente definida.

Se houver conflito entre este prompt e a arquitetura existente:

**priorize a arquitetura existente quando isso preservar qualidade, segurança e compatibilidade**, adaptando o módulo à stack atual.

---

# 2. NOVO MÓDULO

Adicionar uma nova aba principal:

## "Microsegmentação"

Nome interno sugerido:

`Microsegmentation`

ou

`Hybrid Microsegmentation`

Essa aba deverá possuir uma navegação própria:

### Overview

### Network Map

### Flows

### Assets

### Policies

### Attack Paths

### Segmentation

### Simulations

### Analytics

### Integrations

### Settings

A interface deve ser extremamente profissional, com aparência de produto Enterprise Cybersecurity.

Evitar aparência de dashboard genérico.

---

# 3. OBJETIVO DO PRODUTO

O módulo deverá permitir que o usuário responda visualmente:

### "Quem está falando com quem?"

### "O que deveria estar falando com quem?"

### "O que está falando indevidamente?"

### "Quais conexões estão bloqueadas?"

### "Existe movimento lateral?"

### "Quais ativos estão expostos?"

### "Qual política deveria existir?"

### "Se eu bloquear essa comunicação, o que será impactado?"

### "Minha segmentação realmente funciona?"

### "O Auto Pentest conseguiu atravessar alguma zona de segurança?"

---

# 4. ARQUITETURA CONCEITUAL

A solução deverá trabalhar com quatro grandes camadas:

```text
                    ┌─────────────────────────────┐
                    │       USER / SOC / CISO     │
                    └──────────────┬──────────────┘
                                   │
                                   ▼
                    ┌─────────────────────────────┐
                    │     MICROSEGMENTATION UI    │
                    │                             │
                    │ Overview                    │
                    │ Network Map                 │
                    │ Flows                       │
                    │ Policies                    │
                    │ Attack Paths                │
                    │ Simulations                 │
                    └──────────────┬──────────────┘
                                   │
                                   ▼
                    ┌─────────────────────────────┐
                    │       POLICY / RISK ENGINE  │
                    └──────────────┬──────────────┘
                                   │
             ┌─────────────────────┼────────────────────┐
             ▼                     ▼                    ▼
        Kubernetes               VMs                 Cloud
        Cilium                  Linux               AWS/Azure
        Hubble                  Windows             GCP
             │                     │                    │
             └─────────────────────┼────────────────────┘
                                   ▼
                    ┌─────────────────────────────┐
                    │      TELEMETRY / FLOWS      │
                    │ eBPF / Hubble / Prometheus  │
                    └──────────────┬──────────────┘
                                   │
                                   ▼
                    ┌─────────────────────────────┐
                    │      DATA / ANALYTICS       │
                    │ PostgreSQL / TimescaleDB    │
                    │ Redis / Object Storage      │
                    └─────────────────────────────┘
```

---

# 5. TECNOLOGIAS PREFERENCIAIS

Utilize as tecnologias existentes da aplicação quando forem adequadas.

Quando não existir uma decisão prévia, utilizar:

## Frontend

Preferencialmente:

* React
* TypeScript
* Tailwind CSS
* React Query/TanStack Query
* React Flow ou Cytoscape.js
* Recharts
* Lucide Icons

Caso o projeto existente utilize outra stack moderna, adapte-se à stack atual.

---

# 6. BACKEND

Preferência:

### Go

ou, caso a aplicação existente seja Node.js:

### Node.js + TypeScript

O backend deverá possuir:

* REST API;
* WebSocket;
* gRPC quando necessário;
* OpenAPI;
* validação de entrada;
* autenticação;
* autorização;
* RBAC;
* audit logging;
* rate limiting;
* observabilidade;
* tratamento de erros;
* health checks.

---

# 7. NETWORK TELEMETRY

Criar uma camada de abstração chamada:

`Telemetry Provider`

Ela não deve acoplar toda a aplicação diretamente ao Cilium.

Criar uma interface conceitual:

```text
TelemetryProvider
 ├── HubbleProvider
 ├── PrometheusProvider
 ├── FlowLogProvider
 ├── CloudFlowLogProvider
 └── MockProvider
```

O `MockProvider` deverá existir somente para desenvolvimento/testes.

O produto deve permitir futuramente conectar:

* Cilium/Hubble;
* AWS VPC Flow Logs;
* Azure NSG Flow Logs;
* GCP Flow Logs;
* outros collectors.

---

# 8. CILIUM / HUBBLE

Quando Cilium estiver disponível:

Utilizar Hubble Relay para ingestão de flows.

Coletar informações como:

```text
timestamp
source
source_namespace
source_pod
source_ip
source_identity
destination
destination_namespace
destination_pod
destination_ip
destination_identity
source_host
destination_host
source_workload
destination_workload
port
protocol
verdict
traffic_direction
bytes
packets
l7_protocol
http_method
http_path
grpc_service
grpc_method
dns_query
reply
latency
```

Não armazenar dados sensíveis desnecessariamente.

Criar mecanismos de:

* masking;
* retention;
* filtering;
* sampling;
* aggregation.

---

# 9. NORMALIZAÇÃO

Criar um modelo interno universal:

```text
NetworkFlow
```

Exemplo conceitual:

```json
{
  "id": "...",
  "timestamp": "...",
  "source": {
    "type": "kubernetes|vm|host|cloud",
    "id": "...",
    "name": "...",
    "ip": "...",
    "namespace": "...",
    "workload": "..."
  },
  "destination": {
    "type": "...",
    "id": "...",
    "name": "...",
    "ip": "..."
  },
  "network": {
    "protocol": "TCP",
    "port": 443,
    "direction": "EGRESS"
  },
  "application": {
    "protocol": "HTTPS",
    "method": "GET",
    "path": "/api/..."
  },
  "verdict": "FORWARDED",
  "bytes": 12345,
  "packets": 123
}
```

---

# 10. BANCO DE DADOS

Criar modelo de dados preparado para alto volume.

Preferência:

### PostgreSQL + TimescaleDB

Entidades principais:

```text
assets
workloads
hosts
clusters
namespaces
network_flows
flow_aggregations
network_policies
policy_versions
policy_simulations
attack_paths
security_alerts
segmentation_zones
telemetry_sources
integrations
audit_logs
```

Criar índices apropriados.

Não executar queries pesadas diretamente sobre milhões de flows para alimentar o mapa.

Criar:

* agregações;
* materialized views;
* time buckets;
* cache;
* pré-processamento.

---

# 11. NETWORK MAP — PRINCIPAL FUNCIONALIDADE

Criar um mapa de rede interativo de nível Enterprise.

Essa será a funcionalidade visual principal.

O mapa deverá mostrar:

```text
Internet
   │
   ▼
WAF / API
   │
   ▼
Frontend
   │
   ├──────────────► API
   │                  │
   │                  ▼
   │               Database
   │
   └──────────────► External Service
```

Porém os nós serão gerados dinamicamente pelos dados reais.

---

# 12. NODES

Tipos:

```text
Internet
Cloud
Cluster
Namespace
Pod
Deployment
VM
Server
Database
Load Balancer
API
Service
Host
Security Zone
```

Cada node deverá possuir:

* nome;
* tipo;
* IP;
* ambiente;
* sistema operacional;
* tags;
* criticidade;
* owner;
* quantidade de conexões;
* risco;
* quantidade de flows;
* quantidade de drops;
* status de segmentação.

---

# 13. EDGES

Cada conexão deverá possuir:

* origem;
* destino;
* protocolo;
* porta;
* volume;
* packets;
* bytes;
* verdict;
* frequência;
* primeira ocorrência;
* última ocorrência;
* política relacionada;
* risco.

Estados visuais:

### FORWARDED

Conexão permitida.

### DROPPED

Conexão bloqueada.

### ANOMALOUS

Comportamento anômalo.

### ATTACK_PATH

Caminho relacionado a um ataque autorizado detectado pelo Auto Pentest.

### UNKNOWN

Comunicação não classificada.

---

# 14. MAPA INTERATIVO

Implementar:

* zoom;
* pan;
* search;
* filtros;
* agrupamento;
* clustering;
* minimap;
* fullscreen;
* fit-to-screen;
* seleção de node;
* seleção de edge;
* histórico;
* live mode;
* replay mode.

Permitir:

```text
1 min
5 min
15 min
1 hour
6 hours
24 hours
7 days
30 days
```

---

# 15. FILTROS

Criar filtros avançados:

### Environment

* Production
* Homologation
* Development
* DR

### Asset type

* VM
* Kubernetes
* Database
* API
* Server
* Cloud

### Protocol

* TCP
* UDP
* HTTP
* HTTPS
* DNS
* SSH
* RDP
* PostgreSQL
* MySQL

### Verdict

* Forwarded
* Dropped

### Risk

* Critical
* High
* Medium
* Low

### Policy

* Protected
* Partially Protected
* Unprotected

---

# 16. SIDE PANEL

Ao clicar em qualquer node:

Abrir painel lateral.

Mostrar:

```text
Asset

Name
Type
IP
Environment
Owner
Criticality
OS

Security

Risk Score
Segmentation Status
Policy Status

Traffic

Inbound
Outbound
Allowed
Blocked

Connections

Top Sources
Top Destinations

Security Events

Attack Paths
Anomalies
Pentest Findings
```

---

# 17. EDGE INSPECTION

Ao clicar em uma conexão:

mostrar:

```text
SOURCE
   ↓
DESTINATION

Protocol
Port
Direction
Verdict

Traffic Volume
Packets
Bytes

First Seen
Last Seen

Related Policy

Security Context

Attack Context
```

E uma tabela dos flows.

---

# 18. LIVE MODE

Criar botão:

## LIVE

Quando ativado:

* WebSocket;
* novos flows aparecem;
* edges atualizam;
* contadores atualizam;
* novos drops aparecem;
* alertas aparecem;
* attack paths são destacados.

Não atualizar toda a página.

Atualizar somente os componentes afetados.

---

# 19. EXECUTIVE OVERVIEW

Criar dashboard inicial.

KPIs:

### Total Assets

### Active Connections

### Blocked Connections

### Segmentation Coverage

### Unprotected Assets

### Critical Attack Paths

### Policies

### Policy Violations

---

# 20. EXECUTIVE RISK SCORE

Criar:

## Microsegmentation Security Score

De 0–100.

Calcular utilizando:

```text
Asset Coverage
+
Policy Coverage
+
Least Privilege
+
Blocked Lateral Movement
+
Critical Assets Protection
+
Attack Path Exposure
+
Policy Violations
```

Mostrar:

```text
92
SECURE
```

ou:

```text
61
NEEDS ATTENTION
```

O cálculo deverá ser transparente.

Permitir clicar no score e visualizar os fatores.

---

# 21. SEGMENTATION COVERAGE

Mostrar:

```text
Protected Assets       87%
Partially Protected     9%
Unprotected             4%
```

Criar drill-down.

---

# 22. TOP RISKY CONNECTIONS

Criar tabela:

```text
Source
Destination
Port
Protocol
Risk
Reason
Policy
Action
```

Exemplo:

```text
WEB01 → DB01
TCP 5432
HIGH
Unexpected communication
No policy
[Create Policy]
```

---

# 23. POLICIES

Criar aba:

## Policy Management

Mostrar:

```text
Policy Name
Source
Destination
Protocol
Port
Action
Status
Environment
Last Modified
Owner
```

Estados:

```text
Draft
Simulation
Audit
Enforced
Disabled
Rejected
```

---

# 24. NO-CODE POLICY BUILDER

Criar um editor visual.

Fluxo:

```text
SELECT SOURCE
      ↓
SELECT DESTINATION
      ↓
SELECT PROTOCOL
      ↓
SELECT PORT
      ↓
SELECT ACTION
      ↓
SIMULATE
      ↓
APPROVE
      ↓
DEPLOY
```

Exemplo:

```text
frontend-api
      │
      │ TCP 5432
      ▼
database-prod
```

Gerar automaticamente uma policy compatível com Cilium.

---

# 25. YAML PREVIEW

Nunca esconder completamente o código.

O usuário deverá conseguir visualizar:

```yaml
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
...
```

Com:

* syntax highlighting;
* copy;
* download;
* version;
* diff.

---

# 26. POLICY SIMULATION

Essa é uma funcionalidade crítica.

Antes de aplicar uma policy:

## SIMULATE IMPACT

O sistema deverá verificar:

* flows históricos;
* conexões legítimas;
* dependências;
* workloads afetados;
* portas utilizadas;
* comunicação crítica;
* aplicações dependentes.

Resultado:

```text
IMPACT ANALYSIS

Expected blocked flows: 1,842

Potential service disruption:
HIGH

Affected applications:
3

Affected assets:
14

Critical dependencies:
2

Recommendation:
DO NOT ENFORCE
```

Ou:

```text
SAFE TO ENFORCE

Expected blocked flows:
0 legitimate

Confidence:
98%
```

---

# 27. POLICY LEARNING

Criar modo:

## Observe

A plataforma observa o tráfego.

Depois:

## Recommend

A IA recomenda políticas.

Depois:

## Simulate

A plataforma testa impacto.

Depois:

## Approve

Usuário aprova.

Depois:

## Enforce

Policy entra em produção.

Nunca fazer enforcement automático sem autorização explícita.

---

# 28. IA DE MICROSEGMENTAÇÃO

Criar um componente:

# Segmentation AI

A IA deverá analisar:

* flows;
* assets;
* aplicações;
* portas;
* protocolos;
* horários;
* padrões;
* políticas;
* attack paths;
* criticidade.

E gerar recomendações.

Exemplo:

> "A VM APP-01 realiza comunicação TCP/5432 com DB-01. Essa comunicação ocorre 99,8% das vezes dentro do fluxo esperado. Recomenda-se permitir somente APP-01 → DB-01 TCP/5432."

Outra recomendação:

> "APP-02 acessou 17 servidores diferentes utilizando SSH. O comportamento não corresponde ao baseline observado. Recomenda-se restringir SSH ao segmento administrativo."

---

# 29. EXPLAINABILITY

Toda recomendação da IA deve possuir:

```text
Why?

Evidence

Observed behavior

Risk

Recommendation

Expected impact

Confidence
```

Nunca apresentar uma recomendação simplesmente como:

> "AI says block."

---

# 30. ATTACK PATHS

Integrar profundamente com o módulo de Auto Pentest existente.

Criar:

## Attack Path

Modelo:

```text
Internet
   ↓
Public API
   ↓
Web Server
   ↓
Compromised Workload
   ↓
Internal API
   ↓
Database
```

Cada etapa deve ser representada visualmente.

---

# 31. INTEGRAÇÃO COM AUTO PENTEST

Criar API:

```http
POST /api/v1/integrations/pentest/events
```

Payload conceitual:

```json
{
  "scan_id": "...",
  "source_asset": "...",
  "destination_asset": "...",
  "technique": "...",
  "severity": "HIGH",
  "attack_path": [],
  "timestamp": "..."
}
```

Quando o Auto Pentest identificar movimento lateral autorizado:

1. registrar evento;
2. criar attack path;
3. atualizar mapa;
4. aumentar risco;
5. destacar caminho;
6. sugerir política;
7. simular bloqueio;
8. apresentar recomendação.

---

# 32. VISUAL DO ATTACK PATH

No mapa:

```text
SOURCE
  ↓
  ↓  ATTACK
  ↓
COMPROMISED ASSET
  ↓
LATERAL MOVEMENT
  ↓
TARGET
```

Usar destaque visual de alerta.

Não utilizar animações exageradas.

O objetivo é SOC/Enterprise, não videogame.

---

# 33. "WHY IS THIS EXPOSED?"

Adicionar ação contextual:

## Explain Exposure

Ao clicar:

A IA deverá explicar:

```text
Why can APP01 reach DB02?

Observed connection:
TCP/5432

Frequency:
1,242 connections/day

Policy:
None

Business classification:
Unknown

Risk:
HIGH

Recommendation:
Create explicit allow policy and deny all other sources.
```

---

# 34. ATTACK PATH → POLICY

Adicionar botão:

# Protect This Path

Ao clicar:

O sistema deve:

1. analisar caminho;
2. identificar comunicação legítima;
3. identificar comunicação suspeita;
4. gerar policy;
5. simular impacto;
6. apresentar diff;
7. aguardar aprovação.

---

# 35. SEGMENTATION ZONES

Criar conceito de:

## Security Zones

Exemplos:

```text
Internet
DMZ
Web
Application
Database
Management
Backup
Monitoring
Identity
Critical Systems
Development
Production
```

Permitir criar zonas visualmente.

---

# 36. ZERO TRUST VIEW

Criar uma visão:

# Zero Trust

Mostrar:

```text
Implicit Trust
      ↓
Observed
      ↓
Classified
      ↓
Explicit Policy
      ↓
Least Privilege
```

Indicadores:

* Explicitly Allowed;
* Explicitly Denied;
* Unknown;
* Unsegmented.

---

# 37. WINDOWS + LINUX + KUBERNETES

A arquitetura deve ser preparada para ambiente híbrido.

Suportar conceitualmente:

```text
Kubernetes
Linux VM
Windows VM
Bare Metal
Cloud
```

Não assumir que todo ambiente é Kubernetes.

Quando uma fonte não suportar determinada funcionalidade:

* informar claramente;
* degradar graciosamente;
* não inventar dados.

---

# 38. PROVIDER ARCHITECTURE

Criar adapters:

```text
CiliumAdapter
HubbleAdapter
PrometheusAdapter
AWSFlowLogsAdapter
AzureFlowLogsAdapter
GCPFlowLogsAdapter
```

Futuras integrações devem ser adicionáveis sem alterar o core.

---

# 39. OBSERVABILITY

Criar:

```text
Metrics
Logs
Traces
Health
```

Endpoints:

```text
/health
/ready
/metrics
```

Monitorar:

* ingestion rate;
* dropped telemetry;
* processing latency;
* database latency;
* websocket clients;
* policy operations;
* errors.

---

# 40. PERFORMANCE

O mapa deverá suportar grandes ambientes.

Não renderizar milhares de edges individualmente sem agregação.

Implementar:

* clustering;
* aggregation;
* virtualization;
* server-side filtering;
* pagination;
* caching;
* incremental updates.

Meta inicial:

### 500+ nodes

e

### milhares de conexões

sem congelar o browser.

---

# 41. REAL-TIME ARCHITECTURE

Utilizar:

```text
Hubble
   ↓
Collector
   ↓
Normalizer
   ↓
Stream
   ↓
Aggregator
   ↓
WebSocket
   ↓
Frontend
```

O frontend nunca deve consultar milhões de flows diretamente.

---

# 42. REDIS / CACHE

Utilizar Redis, caso compatível com a arquitetura existente, para:

* sessions;
* cache;
* live state;
* aggregation;
* rate limiting;
* temporary simulation state.

---

# 43. AUDIT TRAIL

Toda operação administrativa deverá ser auditada.

Registrar:

```text
user
timestamp
action
resource
old_value
new_value
source_ip
result
```

Exemplos:

```text
POLICY_CREATED
POLICY_SIMULATED
POLICY_APPROVED
POLICY_ENFORCED
POLICY_DISABLED
INTEGRATION_CREATED
```

---

# 44. RBAC

Criar permissões específicas:

```text
microsegmentation.view
microsegmentation.flows
microsegmentation.assets
microsegmentation.policies.view
microsegmentation.policies.create
microsegmentation.policies.simulate
microsegmentation.policies.approve
microsegmentation.policies.enforce
microsegmentation.integrations.manage
```

Separar:

### Viewer

somente leitura.

### Analyst

análise e simulação.

### Security Engineer

criação de policies.

### Approver

aprovação.

### Administrator

configuração.

---

# 45. FOUR-EYES PRINCIPLE

Para ambientes críticos:

Quem cria a policy não necessariamente pode aprová-la.

Implementar workflow:

```text
Engineer
   ↓
Create
   ↓
Simulation
   ↓
Submit
   ↓
Security Approver
   ↓
Approve
   ↓
Deploy
```

---

# 46. POLICY VERSIONING

Toda policy deverá possuir:

```text
version
created_by
approved_by
created_at
updated_at
status
change_reason
```

Permitir:

* diff;
* rollback;
* history.

---

# 47. SAFETY

Nunca aplicar automaticamente uma regra potencialmente disruptiva somente porque a IA recomendou.

Sempre:

```text
Observe
→ Analyze
→ Simulate
→ Recommend
→ Human Approval
→ Enforce
```

---

# 48. SIMULATION ENGINE

Criar um motor interno capaz de responder:

> "O que aconteceria se esta comunicação fosse bloqueada?"

Entrada:

```text
source
destination
protocol
port
action
```

Saída:

```text
flows affected
assets affected
applications affected
critical services affected
risk
confidence
recommendation
```

---

# 49. ANALYTICS

Criar dashboards:

### Traffic Overview

### Blocked Traffic

### Lateral Movement

### Policy Coverage

### Unsegmented Assets

### Top Talkers

### Top Blocked Connections

### Attack Paths

### Policy Violations

### Risk Trends

---

# 50. TIME SERIES

Gráficos:

```text
Connections over time
Blocked traffic
Allowed traffic
Unique assets
Policy violations
Attack paths
```

Intervalos:

```text
1h
6h
24h
7d
30d
90d
```

---

# 51. TOP ATTACKED ASSETS

Tabela:

```text
Asset
Drops
Attack Paths
Risk
Criticality
Last Event
```

---

# 52. POLICY COMPLIANCE

Mostrar:

```text
Assets with policies
Assets without policies
Critical assets protected
Critical assets unprotected
```

---

# 53. UNSEGMENTED ASSETS

Criar uma página específica:

## Unprotected Assets

Mostrar:

```text
Asset
Criticality
Observed connections
Risk
Recommended zone
Recommended policy
```

Botão:

### Generate Protection Plan

---

# 54. PROTECTION PLAN

A IA deverá gerar:

```text
Current State

Risk

Recommended Segmentation

Policies

Potential Impact

Implementation Order
```

Exemplo:

```text
PHASE 1
Observe

PHASE 2
Restrict administrative access

PHASE 3
Restrict database access

PHASE 4
Deny lateral movement

PHASE 5
Validate
```

---

# 55. SIMULATION / VALIDATION

Criar:

## Validate Segmentation

A plataforma deverá permitir validar se as políticas estão funcionando.

Quando houver integração autorizada com ferramentas de simulação, apresentar:

```text
Expected Result
Actual Result
Passed
Failed
Blocked
Unexpectedly Allowed
```

Não executar ações ofensivas automaticamente fora de escopo/autorização.

---

# 56. INFECTION MONKEY / ATTACK SIMULATION

Preparar uma integração opcional com ferramentas de adversary simulation.

Ela deverá ser:

### Explicitamente autorizada.

Nunca executar automaticamente contra ambientes não autorizados.

Fluxo:

```text
Select Authorized Environment
       ↓
Create Simulation
       ↓
Approval
       ↓
Execute
       ↓
Observe
       ↓
Validate Segmentation
       ↓
Generate Report
```

---

# 57. ATTACK PATH VALIDATION

Depois da simulação:

Mostrar:

```text
ATTACK PATH

Source
  ↓
Step 1
  ✓ BLOCKED

Step 2
  ✓ BLOCKED

Target
  ✕ NOT REACHED
```

ou:

```text
CRITICAL

Attack path reached protected asset.

Segmentation control FAILED.
```

---

# 58. INTEGRATIONS

Criar página:

## Integrations

Cards:

```text
Cilium
Hubble
Prometheus
Grafana
Kubernetes
AWS
Azure
GCP
Wazuh
Auto Pentest
SIEM
```

Cada integração deve mostrar:

```text
Status
Last Sync
Events
Errors
Configuration
```

---

# 59. AUTO PENTEST + MICROSEGMENTATION

Criar uma relação bidirecional:

### Auto Pentest encontra vulnerabilidade

↓

### Microsegmentation analisa caminho

↓

### Policy Engine recomenda contenção

↓

### Simulation

↓

### Validation

↓

### Risk Score atualizado

Isso deve criar uma experiência única.

---

# 60. EXEMPLO DE FLUXO

O Auto Pentest descobre:

```text
WEB01
   ↓
TCP/445
   ↓
SERVER02
```

O módulo de microsegmentação verifica:

```text
Existe policy?
Não.

Esse fluxo é normal?
Não.

Existe criticidade?
Alta.

Existe attack path?
Sim.
```

A plataforma apresenta:

```text
CRITICAL LATERAL MOVEMENT

WEB01 → SERVER02

Recommended Action:

Block SMB between these assets.

[SIMULATE]
```

Após simulação:

```text
No legitimate dependencies detected.

SAFE TO ENFORCE
```

Depois:

```text
[REQUEST APPROVAL]
```

---

# 61. DESIGN SYSTEM

A interface deverá seguir princípios Enterprise:

* dark/light mode se já existir;
* responsividade;
* tipografia consistente;
* espaçamento consistente;
* cards discretos;
* tabelas profissionais;
* tooltips;
* breadcrumbs;
* drawers;
* modais;
* command palette;
* keyboard shortcuts.

Não utilizar excesso de:

* gradientes;
* neon;
* sombras exageradas;
* animações;
* elementos decorativos.

---

# 62. MAPA VISUAL

O mapa deverá ser o elemento visual central.

Priorizar:

```text
clarity
hierarchy
density
performance
```

Permitir alternar:

### Logical View

```text
Web → API → DB
```

### Infrastructure View

```text
VM01 → VM02 → VM03
```

### Kubernetes View

```text
Namespace → Deployment → Pod
```

### Security View

```text
Trusted → Restricted → Critical
```

### Attack View

```text
Entry → Compromise → Lateral Movement → Target
```

---

# 63. SEARCH

Implementar busca global:

```text
Search asset
Search IP
Search hostname
Search pod
Search namespace
Search policy
Search attack path
Search flow
```

---

# 64. COMMAND CENTER

Adicionar eventualmente um botão:

## Security Copilot

O usuário poderá perguntar:

> "Quais servidores estão mais expostos?"

> "Mostre os caminhos de ataque críticos."

> "Quais conexões SSH deveriam ser bloqueadas?"

> "O que aconteceria se eu bloquear o acesso da WEB01 ao DB01?"

> "Mostre ativos sem microsegmentação."

A IA deverá consultar os dados reais da plataforma.

Nunca inventar resultados.

---

# 65. AI TOOLS

Criar ferramentas internas para o agente:

```text
get_assets()
get_flows()
get_asset_details()
get_attack_paths()
get_policies()
simulate_policy()
get_risk_score()
get_segmentation_gaps()
recommend_policy()
```

A IA deverá utilizar essas ferramentas antes de responder questões sobre o ambiente.

---

# 66. SECURITY

Implementar:

* TLS;
* mTLS onde aplicável;
* secret management;
* RBAC;
* input validation;
* output validation;
* audit logging;
* SSRF protection;
* CSRF protection quando aplicável;
* secure headers;
* rate limiting;
* tenant isolation;
* encryption at rest;
* encryption in transit.

Nunca colocar secrets no frontend.

---

# 67. MULTI-TENANCY

Se a plataforma atual for multi-tenant, garantir isolamento absoluto:

```text
Tenant A
   X
Tenant B
```

Flows, assets, policies e integrações nunca podem cruzar tenants.

---

# 68. API DESIGN

Criar APIs versionadas:

```text
/api/v1/microsegmentation/overview

/api/v1/microsegmentation/assets

/api/v1/microsegmentation/flows

/api/v1/microsegmentation/graph

/api/v1/microsegmentation/policies

/api/v1/microsegmentation/policies/simulate

/api/v1/microsegmentation/policies/recommend

/api/v1/microsegmentation/attack-paths

/api/v1/microsegmentation/segmentation

/api/v1/microsegmentation/analytics

/api/v1/microsegmentation/integrations

/api/v1/integrations/pentest/events
```

---

# 69. WEBSOCKET

Criar canal:

```text
/ws/microsegmentation
```

Eventos:

```text
FLOW_CREATED
FLOW_DROPPED
ASSET_DISCOVERED
POLICY_CHANGED
ATTACK_PATH_CREATED
ALERT_CREATED
SIMULATION_COMPLETED
```

---

# 70. ERROR HANDLING

Nunca mostrar stack traces para usuários.

Criar:

```text
error code
message
request id
timestamp
```

---

# 71. TESTES

Implementar:

### Unit tests

Para:

* policy engine;
* normalization;
* risk engine;
* simulation engine.

### Integration tests

Para:

* database;
* Hubble;
* APIs;
* WebSocket.

### Frontend tests

Para:

* map;
* filters;
* policy builder;
* drawers;
* simulations.

### E2E

Fluxo mínimo:

```text
Asset
→ Flow
→ Policy
→ Simulation
→ Approval
```

---

# 72. MOCK ENVIRONMENT

Criar um ambiente de demonstração realista.

Gerar assets fictícios:

```text
Internet
WEB-01
WEB-02
API-01
API-02
DB-01
DB-02
K8S-PROD
K8S-HOMOLOG
MONITORING
BACKUP
```

Gerar flows coerentes.

O modo demo deverá alimentar exatamente os mesmos componentes utilizados pelos dados reais.

Não duplicar lógica.

---

# 73. SEED DATA

Criar seeds para:

* assets;
* flows;
* policies;
* attack paths;
* alerts;
* zones.

---

# 74. DOCUMENTAÇÃO

Gerar:

```text
README.md

ARCHITECTURE.md

API.md

DATABASE.md

DEPLOYMENT.md

SECURITY.md

MICROSEGMENTATION.md

INTEGRATIONS.md

TROUBLESHOOTING.md
```

---

# 75. INFRASTRUCTURE AS CODE

Quando necessário, criar:

```text
Dockerfile
docker-compose.yml
.env.example
Helm charts
Kubernetes manifests
Terraform
```

Não sobrescrever configurações existentes.

Criar arquivos separados para o novo módulo quando possível.

---

# 76. MIGRATIONS

Banco deverá utilizar migrations.

Nunca modificar schema de produção manualmente.

Criar:

```text
001_microsegmentation_initial.sql
002_network_flows.sql
003_policies.sql
004_attack_paths.sql
```

Adaptar ao framework de migration já utilizado pelo projeto.

---

# 77. OBSERVABILITY DASHBOARD

Criar métricas internas:

```text
flows/sec
events/sec
processing latency
database latency
policy simulation time
websocket connections
active integrations
errors
```

---

# 78. ALERTING

Criar alertas:

### Critical Attack Path

### Unexpected Lateral Movement

### High Drop Rate

### Unsegmented Critical Asset

### Policy Violation

### Telemetry Failure

### Integration Failure

---

# 79. RELAÇÃO COM RISCO

A microsegmentação deverá alimentar o Risk Engine existente.

Exemplo:

```text
Pentest Finding
      +
Asset Criticality
      +
Attack Path
      +
Segmentation Gap
      +
Policy Violation
      =
Business Cyber Risk
```

Não criar um segundo Risk Engine se já existir um.

Integrar ao existente.

---

# 80. DASHBOARD EXECUTIVO

Criar uma visão extremamente simples para CISO/C-Level:

```text
MICROSEGMENTATION SECURITY

Security Score        87
Protected Assets      94%
Critical Assets       98%
Attack Paths          3
Blocked Lateral       12,492
Policy Coverage       91%
```

Abaixo:

```text
Risk Trend

Critical Attack Paths

Top Exposed Assets

Segmentation Gaps
```

---

# 81. RELATÓRIOS

Permitir gerar relatório:

## Microsegmentation Security Report

Conteúdo:

```text
Executive Summary
Security Score
Asset Coverage
Policy Coverage
Attack Paths
Top Risks
Unsegmented Assets
Policy Changes
Simulation Results
Recommendations
```

---

# 82. PRINCÍPIO DE IMPLEMENTAÇÃO

Não implemente tudo como um monolito.

Separar claramente:

```text
frontend
backend
domain
telemetry
policy-engine
simulation-engine
risk-engine
integrations
storage
workers
```

Seguir princípios:

* SOLID;
* Clean Architecture;
* Domain Driven Design quando aplicável;
* dependency inversion;
* observability;
* testability.

---

# 83. NÃO FAZER

Não:

* remover funcionalidades existentes;
* quebrar autenticação;
* criar dados falsos em produção;
* aplicar policies automaticamente;
* executar pentest não autorizado;
* armazenar secrets no código;
* acoplar frontend diretamente ao Kubernetes;
* consultar milhões de flows no browser;
* criar dashboards apenas visuais sem backend;
* duplicar o Risk Engine existente;
* criar uma segunda arquitetura desnecessária;
* substituir componentes existentes sem justificativa.

---

# 84. ORDEM DE IMPLEMENTAÇÃO

Você deverá trabalhar nesta ordem:

## FASE 0 — DISCOVERY

Inspecionar aplicação existente.

Entregar:

```text
Architecture Assessment
Technology Stack
Database
Routes
Components
Integration Points
Recommended Integration Strategy
```

---

## FASE 1 — FOUNDATION

Implementar:

* database;
* migrations;
* domain models;
* API;
* telemetry abstraction;
* configuration;
* logging.

---

## FASE 2 — ASSET & FLOW ENGINE

Implementar:

* collectors;
* normalization;
* storage;
* aggregation;
* APIs;
* WebSocket.

---

## FASE 3 — NETWORK MAP

Implementar:

* graph;
* nodes;
* edges;
* filters;
* search;
* live mode;
* drawers.

---

## FASE 4 — ANALYTICS

Implementar:

* KPIs;
* charts;
* risk score;
* segmentation coverage;
* top risks.

---

## FASE 5 — POLICY ENGINE

Implementar:

* policy model;
* visual builder;
* YAML generator;
* versioning;
* audit.

---

## FASE 6 — SIMULATION

Implementar:

* impact analysis;
* dependency analysis;
* risk;
* confidence;
* recommendations.

---

## FASE 7 — AUTO PENTEST

Integrar:

```text
Pentest
↓
Attack Path
↓
Segmentation
↓
Policy Recommendation
↓
Simulation
```

---

## FASE 8 — AI

Implementar:

* segmentation recommendations;
* explanations;
* security copilot;
* anomaly analysis;
* attack path analysis.

---

## FASE 9 — ENTERPRISE HARDENING

Implementar:

* RBAC;
* audit;
* mTLS;
* rate limits;
* tenant isolation;
* security headers;
* observability.

---

## FASE 10 — TESTING

Executar:

```text
Unit
Integration
E2E
Performance
Security
Regression
```

---

# 85. DEFINITION OF DONE

A funcionalidade somente estará concluída quando:

### Frontend

* [ ] Aba disponível
* [ ] Navigation funcionando
* [ ] Network Map funcionando
* [ ] Live Mode funcionando
* [ ] Filters funcionando
* [ ] Asset details funcionando
* [ ] Flow details funcionando
* [ ] Policies funcionando
* [ ] Simulation funcionando
* [ ] Attack Paths funcionando
* [ ] Analytics funcionando

### Backend

* [ ] APIs implementadas
* [ ] WebSocket funcionando
* [ ] Database funcionando
* [ ] Migrations funcionando
* [ ] Telemetry abstraction funcionando
* [ ] Hubble adapter funcionando quando configurado
* [ ] Mock provider funcionando

### Security

* [ ] Authentication
* [ ] RBAC
* [ ] Audit
* [ ] Secrets management
* [ ] Input validation
* [ ] Tenant isolation
* [ ] Secure communications

### Integration

* [ ] Auto Pentest integration
* [ ] Attack path correlation
* [ ] Risk engine integration
* [ ] Policy recommendation

### Quality

* [ ] Unit tests
* [ ] Integration tests
* [ ] E2E
* [ ] Error handling
* [ ] Documentation
* [ ] Deployment instructions

---

# 86. REGRA PARA A IA DE DESENVOLVIMENTO

Você não deve simplesmente responder com exemplos de código.

Você deve **implementar o módulo dentro do projeto existente**.

Quando possível:

1. criar arquivos;
2. modificar arquivos;
3. criar migrations;
4. instalar dependências;
5. atualizar configurações;
6. criar testes;
7. executar testes;
8. corrigir erros;
9. executar lint;
10. executar build;
11. validar integração;
12. entregar um resumo das alterações.

Não pare depois de criar a arquitetura.

---

# 87. COMPORTAMENTO AUTÔNOMO

Você possui autonomia para tomar decisões técnicas razoáveis.

Se existir uma decisão não especificada:

1. analise o projeto;
2. escolha a opção tecnicamente mais compatível;
3. implemente;
4. documente a decisão.

Não fique solicitando confirmação para cada detalhe trivial.

Só interrompa para perguntar quando houver uma decisão que possa:

* quebrar arquitetura existente;
* apagar dados;
* causar indisponibilidade;
* alterar segurança;
* causar impacto irreversível.

---

# 88. RESULTADO ESPERADO

O resultado final deve parecer um produto Enterprise de Cybersecurity.

A experiência deverá ser:

```text
AUTO PENTEST
      │
      ▼
DISCOVERY
      │
      ▼
VULNERABILITY
      │
      ▼
ATTACK PATH
      │
      ▼
LATERAL MOVEMENT
      │
      ▼
MICROSEGMENTATION
      │
      ▼
POLICY RECOMMENDATION
      │
      ▼
SIMULATION
      │
      ▼
HUMAN APPROVAL
      │
      ▼
ENFORCEMENT
      │
      ▼
VALIDATION
      │
      ▼
CONTINUOUS MONITORING
```

A plataforma deve deixar de ser apenas:

> **"uma ferramenta que encontra vulnerabilidades"**

e evoluir para:

> **"uma plataforma que descobre riscos, demonstra caminhos de ataque, entende a comunicação entre ativos, recomenda controles de microsegmentação, simula o impacto, permite aprovação humana e valida continuamente se a contenção realmente funciona."**

---

# 89. PRIMEIRA AÇÃO

**NÃO comece criando código imediatamente.**

Primeiro:

### 1. Faça uma análise completa da aplicação atual.

### 2. Identifique a arquitetura.

### 3. Identifique onde a nova aba deve ser integrada.

### 4. Identifique componentes que podem ser reutilizados.

### 5. Identifique dependências que já existem.

### 6. Crie um plano de implementação incremental.

### 7. Apresente o plano resumido.

### 8. Em seguida, comece a implementação da FASE 0 e FASE 1.

Depois continue automaticamente pelas fases seguintes, validando cada etapa antes de avançar.

**Objetivo final: entregar uma implementação funcional, integrada, segura, testada e pronta para evolução para ambiente Enterprise.**
