"""
Natural Language Security Assistant API Router

Translates operator prompts into technical strategies and executes authorized tasks.
"""
from typing import Optional, Any
from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel
from app.api.deps import CurrentUser, DbSession, RequirePentester
from app.services.nl_planner import NLPlannerService
from app.services.audit import log_action

router = APIRouter()


class NLPromptRequest(BaseModel):
    prompt: str


class ProposedActionResponse(BaseModel):
    step_number: int
    agent_type: str
    test_type: str
    target: str
    method: str
    description: str
    policy_status: str
    policy_reason: str


class StrategyResponse(BaseModel):
    raw_prompt: str
    interpreted_goal: str
    scan_mode: str
    suggested_agents: list[str]
    hypotheses: list[dict[str, Any]]
    action_plan: list[ProposedActionResponse]
    policy_summary: dict[str, int]
    requires_human_approval: bool
    created_at: str


@router.post("/{project_id}/assistant/plan", response_model=StrategyResponse)
async def create_strategy_from_prompt(
    project_id: str,
    body: NLPromptRequest,
    current_user: CurrentUser,
    db: DbSession,
    request: Request,
):
    """
    Translates a human prompt into a structured, policy-checked security assessment plan.
    """
    if not body.prompt.strip():
        raise HTTPException(status_code=400, detail="Prompt cannot be empty.")

    service = NLPlannerService(db)
    try:
        strategy = await service.generate_strategy_from_prompt(
            project_id=project_id,
            human_prompt=body.prompt,
        )

        await log_action(
            db=db,
            user_id=current_user.id,
            action="NL_STRATEGY_GENERATED",
            resource_type="Project",
            resource_id=project_id,
            details={"prompt": body.prompt, "agents": strategy.suggested_agents},
            request=request,
        )

        return strategy
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
