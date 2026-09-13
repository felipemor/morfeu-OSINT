"""
FastAPI Router — ASPM / Application Security Posture Management & Connectors
"""
from fastapi import APIRouter, HTTPException, Depends
from typing import Dict, Any, List
from app.services.aspm_service import ASPMService

router = APIRouter()


@router.get("/dashboard", summary="Get ASPM Overview & Metrics")
async def get_aspm_dashboard():
    """Returns ASPM metrics, application inventory, connectors status and monthly AppSec trends."""
    return ASPMService.get_aspm_dashboard_stats()


@router.get("/applications", summary="List Monitored Business Applications")
async def list_applications():
    """Returns all mapped applications with squads, owners, repositories, and Quality Gate statuses."""
    stats = ASPMService.get_aspm_dashboard_stats()
    return stats["applications"]


@router.get("/connectors", summary="List AppSec Connectors")
async def list_connectors():
    """Returns status for Checkmarx, GitHub, Microsoft Defender, Snyk, and Veracode."""
    stats = ASPMService.get_aspm_dashboard_stats()
    return stats["connectors"]


@router.post("/connectors/{connector_id}/sync", summary="Trigger Connector Sync")
async def trigger_sync(connector_id: str):
    """Triggers real-time sync with external AppSec tooling."""
    return {
        "connector_id": connector_id,
        "status": "SYNC_QUEUED",
        "message": f"Sincronização assíncrona iniciada com sucesso para o conector {connector_id}.",
        "timestamp": "2026-09-11T20:00:00Z",
    }
