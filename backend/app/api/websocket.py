"""
WebSocket — Live Pentest Console

Streams real-time agent logs to connected clients using WebSocket.
"""
import asyncio
import json
from typing import Optional
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query
from sqlalchemy import select
import structlog

router = APIRouter()
logger = structlog.get_logger(__name__)


class ConnectionManager:
    """Manages WebSocket connections per scan_id."""

    def __init__(self):
        self.active_connections: dict[str, list[WebSocket]] = {}

    async def connect(self, scan_id: str, websocket: WebSocket):
        await websocket.accept()
        if scan_id not in self.active_connections:
            self.active_connections[scan_id] = []
        self.active_connections[scan_id].append(websocket)
        logger.info("WebSocket connected", scan_id=scan_id)

    def disconnect(self, scan_id: str, websocket: WebSocket):
        if scan_id in self.active_connections:
            self.active_connections[scan_id].remove(websocket)
            if not self.active_connections[scan_id]:
                del self.active_connections[scan_id]

    async def broadcast(self, scan_id: str, message: dict):
        """Send message to all clients watching this scan."""
        if scan_id not in self.active_connections:
            return

        dead = []
        for ws in self.active_connections[scan_id]:
            try:
                await ws.send_json(message)
            except Exception:
                dead.append(ws)

        for ws in dead:
            self.active_connections[scan_id].remove(ws)


manager = ConnectionManager()


@router.websocket("/ws/scan/{scan_id}")
async def scan_websocket(websocket: WebSocket, scan_id: str):
    """
    WebSocket endpoint for live pentest console.
    Streams agent logs in real-time.
    """
    await manager.connect(scan_id, websocket)

    try:
        # Stream recent logs then keep polling for new ones
        from app.core.database import AsyncSessionLocal
        from app.models import AgentLog, Scan

        last_log_id = None

        # Send initial state
        async with AsyncSessionLocal() as db:
            scan_result = await db.execute(select(Scan).where(Scan.id == scan_id))
            scan = scan_result.scalar_one_or_none()
            if scan:
                await websocket.send_json({
                    "type": "scan_state",
                    "data": {
                        "scan_id": scan.id,
                        "status": scan.status.value,
                        "mode": scan.mode.value,
                        "progress": scan.progress,
                        "phase": scan.current_phase,
                    }
                })

        while True:
            async with AsyncSessionLocal() as db:
                # Poll for new logs
                query = select(AgentLog).where(AgentLog.scan_id == scan_id)
                if last_log_id:
                    # Get logs after the last one we sent
                    from sqlalchemy import text
                    query = query.where(AgentLog.id > last_log_id)

                query = query.order_by(AgentLog.timestamp).limit(50)
                result = await db.execute(query)
                logs = result.scalars().all()

                for log in logs:
                    await websocket.send_json({
                        "type": "agent_log",
                        "data": {
                            "id": log.id,
                            "timestamp": log.timestamp.isoformat(),
                            "agent": log.agent_type.value,
                            "level": log.level,
                            "message": log.message,
                            "target": log.target,
                            "extra": log.extra_data,
                        }
                    })
                    last_log_id = log.id

                # Check scan status
                scan_result = await db.execute(select(Scan).where(Scan.id == scan_id))
                scan = scan_result.scalar_one_or_none()
                if scan:
                    await websocket.send_json({
                        "type": "scan_progress",
                        "data": {
                            "status": scan.status.value,
                            "progress": scan.progress,
                            "phase": scan.current_phase,
                            "assets": scan.assets_discovered,
                            "endpoints": scan.endpoints_found,
                            "findings": scan.findings_count,
                        }
                    })

                    # Stop polling if scan is complete
                    if scan.status.value in ("COMPLETED", "FAILED", "KILLED"):
                        await websocket.send_json({"type": "scan_complete", "data": {"status": scan.status.value}})
                        break

            await asyncio.sleep(2)  # Poll every 2 seconds

    except WebSocketDisconnect:
        logger.info("WebSocket disconnected", scan_id=scan_id)
    except Exception as e:
        logger.error("WebSocket error", scan_id=scan_id, error=str(e))
    finally:
        manager.disconnect(scan_id, websocket)


async def broadcast_to_scan(scan_id: str, message: dict):
    """Called by agents to push real-time updates to connected clients."""
    await manager.broadcast(scan_id, message)
