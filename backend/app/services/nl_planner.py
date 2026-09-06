"""
Natural Language Security Assistant & Intent Planner Service

Translates human operator prompts (Portuguese or English) into structured technical
assessment strategies, prioritized security hypotheses, and policy-governed execution tasks.
"""
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional, Any
import re
import structlog
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.models import Project, Scope, SecurityHypothesis, HypothesisStatus, Severity, ScanMode
from app.security.policy_engine import PolicyEngine, PolicyConfig, PolicyDecision
from app.core.scope_validator import ScopeValidator

logger = structlog.get_logger(__name__)


@dataclass
class ProposedAction:
    step_number: int
    agent_type: str  # RECON, WEB_CRAWLER, BROWSER_AGENT, API_AGENT, VULNERABILITY
    test_type: str
    target: str
    method: str = "GET"
    description: str = ""
    parameters: dict = field(default_factory=dict)
    policy_status: str = "ALLOW"
    policy_reason: str = ""


@dataclass
class AssessmentStrategy:
    raw_prompt: str
    interpreted_goal: str
    scan_mode: str
    suggested_agents: list[str]
    hypotheses: list[dict[str, Any]]
    action_plan: list[ProposedAction]
    policy_summary: dict[str, int]
    requires_human_approval: bool
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class NLPlannerService:
    """Parses natural language directives and structures them into authorized pentest strategies."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def generate_strategy_from_prompt(
        self,
        project_id: str,
        human_prompt: str,
    ) -> AssessmentStrategy:
        """
        Interprets human natural language instruction, validates against project scope,
        and produces a structured assessment strategy.
        """
        # 1. Fetch project and scope
        proj_res = await self.db.execute(select(Project).where(Project.id == project_id))
        project = proj_res.scalar_one_or_none()
        if not project:
            raise ValueError(f"Project {project_id} not found.")

        scope_res = await self.db.execute(select(Scope).where(Scope.project_id == project_id))
        scope = scope_res.scalar_one_or_none()

        allowed_domains = scope.allowed_domains if scope else []
        allowed_ips = scope.allowed_ips if scope else []
        primary_target = allowed_domains[0] if allowed_domains else (allowed_ips[0] if allowed_ips else "authorized.local")
        base_url = f"https://{primary_target}" if not primary_target.startswith("http") else primary_target

        # 2. Extract intents from natural language prompt
        prompt_lower = human_prompt.lower()

        intents = {
            "recon": any(kw in prompt_lower for kw in ["recon", "descobrir", "discover", "subdomínio", "subdomain", "ativos", "assets", "mapear infra", "portas", "ports"]),
            "api": any(kw in prompt_lower for kw in ["api", "rest", "graphql", "swagger", "openapi", "endpoints", "json", "postman", "schema"]),
            "browser": any(kw in prompt_lower for kw in ["browser", "navegador", "navegar", "dom", "login", "formulário", "form", "clicar", "screenshot", "frontend", "visual"]),
            "auth": any(kw in prompt_lower for kw in ["auth", "autenticação", "jwt", "token", "login", "bola", "idor", "autorização", "privilégio", "permissão", "rbac", "bfla"]),
            "headers_cors": any(kw in prompt_lower for kw in ["header", "cabecalho", "cors", "cookie", "csp", "hsts", "flags", "configuração"]),
            "compliance": any(kw in prompt_lower for kw in ["compliance", "conformidade", "owasp", "cis", "nist", "iso", "relatório"]),
            "full_scan": any(kw in prompt_lower for kw in ["completo", "full", "tudo", "todos os testes", "pentest completo", "all"]),
        }

        # If no specific intent matched, default to balanced assessment
        if not any(intents.values()):
            intents["recon"] = True
            intents["api"] = True
            intents["headers_cors"] = True

        if intents["full_scan"]:
            for k in intents:
                intents[k] = True

        # 3. Formulate Action Plan and Hypotheses
        actions: list[ProposedAction] = []
        hypotheses: list[dict[str, Any]] = []
        suggested_agents: set[str] = set()
        step = 1

        scope_validator = ScopeValidator(
            allowed_domains=allowed_domains,
            allowed_ips=allowed_ips,
            allow_private_ips=scope.allow_private_ips if scope else False,
        )
        policy_engine = PolicyEngine(
            scope_validator=scope_validator,
            config=PolicyConfig(
                environment=scope.environment if scope else "development",
                max_requests_per_minute=scope.max_requests_per_minute if scope else 30,
            ),
        )

        # Step: Recon & Asset Discovery
        if intents["recon"]:
            suggested_agents.add("RECON")
            actions.append(ProposedAction(
                step_number=step,
                agent_type="RECON",
                test_type="ASSET_DISCOVERY",
                target=base_url,
                method="GET",
                description=f"Executar fingerprinting HTTP e descoberta de subdomínios autorizados para {primary_target}.",
            ))
            step += 1

        # Step: Browser & Form Discovery
        if intents["browser"]:
            suggested_agents.add("BROWSER_AGENT")
            actions.append(ProposedAction(
                step_number=step,
                agent_type="BROWSER_AGENT",
                test_type="BROWSER_NAVIGATION",
                target=base_url,
                method="GET",
                description="Iniciar Secure Browser com isolamento de contexto para mapear formulários, SPA routes e capturar evidência visual.",
            ))
            hypotheses.append({
                "code": "H_NL_01",
                "title": "Exposição de Rotas e Formulários na Interface Web",
                "reasoning": ["A interface web pode conter formulários sem proteção anti-CSRF ou endpoints com parâmetros manipuláveis."],
                "confidence": 75,
                "priority": "MEDIUM",
                "test_type": "BROWSER_INSPECTION",
            })
            step += 1

        # Step: API & Schema Discovery
        if intents["api"]:
            suggested_agents.add("API_AGENT")
            actions.append(ProposedAction(
                step_number=step,
                agent_type="API_AGENT",
                test_type="OPENAPI_SCHEMA_DISCOVERY",
                target=f"{base_url}/openapi.json",
                method="GET",
                description="Verificar exposição de documentação de schemas OpenAPI / Swagger / GraphQL.",
            ))
            hypotheses.append({
                "code": "H_NL_02",
                "title": "Documentação e Endpoints de API Expostos",
                "reasoning": ["APIs frequentemente expõem schemas públicos que revelam parâmetros internos e endpoints administrativos."],
                "confidence": 85,
                "priority": "HIGH",
                "test_type": "API_DISCOVERY",
            })
            step += 1

        # Step: Auth & Authorization (BOLA/IDOR/BFLA)
        if intents["auth"]:
            suggested_agents.add("API_AGENT")
            actions.append(ProposedAction(
                step_number=step,
                agent_type="API_AGENT",
                test_type="BOLA_VALIDATION",
                target=f"{base_url}/api/users",
                method="GET",
                description="Validar limites de autorização de objetos (BOLA) e controle de acesso baseado em papéis.",
            ))
            hypotheses.append({
                "code": "H_NL_03",
                "title": "Potencial Fragilidade de Autorização em Nível de Objeto (BOLA / IDOR)",
                "reasoning": ["Endpoints com parâmetros de identificação devem ser validados contra acessos horizontais não autorizados."],
                "confidence": 88,
                "priority": "HIGH",
                "test_type": "BOLA_VALIDATION",
            })
            step += 1

        # Step: Headers, CORS & Cookie Flags
        if intents["headers_cors"]:
            suggested_agents.add("VULNERABILITY")
            actions.append(ProposedAction(
                step_number=step,
                agent_type="VULNERABILITY",
                test_type="HEADER_CORS_INSPECTION",
                target=base_url,
                method="GET",
                description="Inspecionar cabeçalhos de segurança (HSTS, CSP, X-Frame-Options), configuração de CORS e flags de cookies.",
            ))
            step += 1

        # 4. Evaluate each action against Policy Engine
        policy_counts = {"ALLOW": 0, "APPROVAL_REQUIRED": 0, "DENY": 0}
        requires_approval = False

        for action in actions:
            p_res = policy_engine.evaluate_request(
                target_url=action.target,
                method=action.method,
                test_type=action.test_type,
                agent_type=action.agent_type,
                project_id=project_id,
            )
            action.policy_status = p_res.decision.value
            action.policy_reason = p_res.reason
            policy_counts[p_res.decision.value] = policy_counts.get(p_res.decision.value, 0) + 1

            if p_res.decision == PolicyDecision.APPROVAL_REQUIRED:
                requires_approval = True

        interpreted_goal = f"Plano de avaliação estruturado para '{human_prompt[:100]}...' focando em: " + ", ".join(suggested_agents)

        strategy = AssessmentStrategy(
            raw_prompt=human_prompt,
            interpreted_goal=interpreted_goal,
            scan_mode="SAFE_ACTIVE" if any([intents["api"], intents["auth"]]) else "PASSIVE",
            suggested_agents=list(suggested_agents),
            hypotheses=hypotheses,
            action_plan=actions,
            policy_summary=policy_counts,
            requires_human_approval=requires_approval,
        )

        logger.info(
            "Natural Language Strategy generated",
            project_id=project_id,
            actions_count=len(actions),
            hypotheses_count=len(hypotheses),
        )

        return strategy
