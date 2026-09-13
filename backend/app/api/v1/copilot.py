"""
FastAPI Router — AI Security Copilot Analyst
"""
from fastapi import APIRouter, HTTPException
from typing import Dict, Any, List
from pydantic import BaseModel
from app.services.security_copilot_service import SecurityCopilotService

router = APIRouter()


class CopilotQueryRequest(BaseModel):
    query: str
    role: str = "PENTESTER"


@router.post("/query", summary="Query AI Security Copilot")
async def query_copilot(payload: CopilotQueryRequest):
    """Executes contextual posture intelligence query backed by live telemetry and compliance data."""
    return await SecurityCopilotService.query_copilot(question=payload.query, user_role=payload.role)
