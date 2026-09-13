"""
FastAPI Router — Executive Data Mart, 12-Month Posture Trends & Storytelling
"""
from fastapi import APIRouter
from typing import Dict, Any, List
from app.services.snapshot_datamart_service import SnapshotDataMartService

router = APIRouter()


@router.get("/executive-summary", summary="Get Executive Summary & 12-Month Trends")
async def get_executive_summary():
    """Returns historical 12-month posture snapshots, MoM/YoY calculations, and automated executive storytelling narratives."""
    return SnapshotDataMartService.get_executive_summary()
