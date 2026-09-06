"""
Script to wipe all projects, scans, findings, logs, and reset DB to a clean state.
"""
import asyncio
from sqlalchemy import text
from app.core.database import AsyncSessionLocal
from app.services.bootstrap import bootstrap_admin_user
from app.models import (
    AuditLog, AgentLog, BaselineDrift, CrossPlaneCorrelation, Evidence,
    Finding, Endpoint, Asset, Scope, Scan, Approval, Report, Project,
    EndpointAgent, AgentCheckResult
)

async def reset_all_data():
    if AsyncSessionLocal is None:
        print("Database not configured.")
        return

    async with AsyncSessionLocal() as session:
        try:
            print("Cleaning all projects, scans, findings, and logs...")
            # Delete in order of dependencies
            await session.execute(text("DELETE FROM agent_check_results;"))
            await session.execute(text("DELETE FROM baseline_drifts;"))
            await session.execute(text("DELETE FROM cross_plane_correlations;"))
            await session.execute(text("DELETE FROM agent_logs;"))
            await session.execute(text("DELETE FROM audit_logs;"))
            await session.execute(text("DELETE FROM evidences;"))
            await session.execute(text("DELETE FROM findings;"))
            await session.execute(text("DELETE FROM endpoints;"))
            await session.execute(text("DELETE FROM assets;"))
            await session.execute(text("DELETE FROM endpoint_agents;"))
            await session.execute(text("DELETE FROM scopes;"))
            await session.execute(text("DELETE FROM scans;"))
            await session.execute(text("DELETE FROM approvals;"))
            await session.execute(text("DELETE FROM reports;"))
            await session.execute(text("DELETE FROM projects;"))
            await session.commit()
            print("✅ All projects, scans, logs, and artifacts successfully deleted.")
        except Exception as e:
            print(f"Error resetting data: {e}")
            await session.rollback()

    # Re-bootstrap admin user if needed
    await bootstrap_admin_user()
    print("✅ System successfully reset to clean zero-state.")

if __name__ == "__main__":
    asyncio.run(reset_all_data())
