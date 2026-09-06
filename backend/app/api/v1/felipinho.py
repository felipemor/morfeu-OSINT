"""
Felipinho AI Router — morfeusec OSINT
Interactive AI Assistant for general interpretations, technical queries, and guidance.
"""
from typing import Optional, Dict, Any, List
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel

from app.api.deps import CurrentUser
from app.services.felipinho_service import felipinho_service

router = APIRouter()


class FelipinhoChatRequest(BaseModel):
    message: str
    context: Optional[Dict[str, Any]] = None
    history: Optional[List[Dict[str, str]]] = None


@router.post("/chat", status_code=status.HTTP_200_OK)
async def chat_with_felipinho(
    payload: FelipinhoChatRequest,
    current_user: CurrentUser = None,
):
    """
    Sends a query to Felipinho AI and returns structured technical interpretation.
    """
    if not payload.message or not payload.message.strip():
        raise HTTPException(status_code=400, detail="A mensagem não pode estar vazia.")

    return await felipinho_service.answer_query(
        message=payload.message,
        context=payload.context,
    )
