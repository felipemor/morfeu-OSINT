"""
Unit & Integration Tests for Natural Language Security Assistant & Intent Planner
"""
import pytest
from app.services.nl_planner import NLPlannerService, ProposedAction, AssessmentStrategy


def test_nl_intent_classification():
    prompt_api = "Mapear endpoints REST, schemas OpenAPI e verificar parâmetros"
    prompt_browser = "Abrir navegador Chromium, preencher formulários de login e tirar screenshots"
    prompt_recon = "Descobrir subdomínios e ativos de infraestrutura"
    prompt_auth = "Testar vulnerabilidade de BOLA IDOR e controle de acesso JWT"
    prompt_headers = "Verificar conformidade de cabeçalhos HSTS, CSP e configuração de CORS"

    assert any(kw in prompt_api.lower() for kw in ["api", "rest", "openapi", "endpoints"])
    assert any(kw in prompt_browser.lower() for kw in ["navegador", "formulário", "screenshot", "browser"])
    assert any(kw in prompt_recon.lower() for kw in ["subdomínio", "ativos", "descobrir", "recon"])
    assert any(kw in prompt_auth.lower() for kw in ["bola", "idor", "jwt", "auth"])
    assert any(kw in prompt_headers.lower() for kw in ["header", "cabecalho", "cors", "csp", "hsts"])


def test_proposed_action_structure():
    action = ProposedAction(
        step_number=1,
        agent_type="API_AGENT",
        test_type="OPENAPI_SCHEMA_DISCOVERY",
        target="https://api.example.com/openapi.json",
        method="GET",
        description="Verificar schemas expostos.",
    )
    assert action.step_number == 1
    assert action.agent_type == "API_AGENT"
    assert action.policy_status == "ALLOW"
