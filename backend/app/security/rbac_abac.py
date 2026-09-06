"""
RBAC + ABAC Contextual Authorization Engine

Implements Role-Based and Attribute-Based Access Control:
Context: User + Organization + Project + Environment + Asset + Action
"""
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Any
import structlog

from app.models import UserRole

logger = structlog.get_logger(__name__)


class Action(str, Enum):
    # Project & Scope
    VIEW_PROJECT = "project:view"
    CREATE_PROJECT = "project:create"
    EDIT_PROJECT = "project:edit"
    DELETE_PROJECT = "project:delete"
    CONFIGURE_SCOPE = "scope:configure"
    CONFIRM_AUTHORIZATION = "scope:authorize"

    # Scans & Execution
    START_SCAN = "scan:start"
    STOP_SCAN = "scan:stop"
    KILL_SWITCH = "scan:kill"
    RETEST_FINDING = "finding:retest"

    # Findings & Reports
    VIEW_FINDINGS = "findings:view"
    EDIT_FINDING = "findings:edit"
    TRIAGE_FINDING = "findings:triage"
    VIEW_REPORTS = "reports:view"
    GENERATE_REPORT = "reports:generate"

    # Approvals & Audits
    VIEW_AUDIT_LOGS = "audit:view"
    APPROVE_AI_ACTION = "ai_action:approve"
    REJECT_AI_ACTION = "ai_action:reject"
    MANAGE_USERS = "users:manage"


# Role-Permission Mapping Matrix (Base RBAC)
ROLE_PERMISSIONS: dict[UserRole, set[Action]] = {
    UserRole.ADMIN: set(Action),  # All actions
    UserRole.SECURITY_MANAGER: {
        Action.VIEW_PROJECT, Action.CREATE_PROJECT, Action.EDIT_PROJECT,
        Action.CONFIGURE_SCOPE, Action.CONFIRM_AUTHORIZATION,
        Action.START_SCAN, Action.STOP_SCAN, Action.KILL_SWITCH,
        Action.RETEST_FINDING, Action.VIEW_FINDINGS, Action.EDIT_FINDING,
        Action.TRIAGE_FINDING, Action.VIEW_REPORTS, Action.GENERATE_REPORT,
        Action.VIEW_AUDIT_LOGS, Action.APPROVE_AI_ACTION, Action.REJECT_AI_ACTION,
    },
    UserRole.PENTESTER: {
        Action.VIEW_PROJECT, Action.CREATE_PROJECT, Action.EDIT_PROJECT,
        Action.CONFIGURE_SCOPE, Action.START_SCAN, Action.STOP_SCAN,
        Action.KILL_SWITCH, Action.RETEST_FINDING, Action.VIEW_FINDINGS,
        Action.EDIT_FINDING, Action.TRIAGE_FINDING, Action.VIEW_REPORTS,
        Action.GENERATE_REPORT, Action.VIEW_AUDIT_LOGS,
    },
    UserRole.ANALYST: {
        Action.VIEW_PROJECT, Action.VIEW_FINDINGS, Action.TRIAGE_FINDING,
        Action.VIEW_REPORTS, Action.GENERATE_REPORT, Action.VIEW_AUDIT_LOGS,
    },
    UserRole.AUDITOR: {
        Action.VIEW_PROJECT, Action.VIEW_FINDINGS, Action.VIEW_REPORTS,
        Action.VIEW_AUDIT_LOGS,
    },
    UserRole.READONLY: {
        Action.VIEW_PROJECT, Action.VIEW_FINDINGS, Action.VIEW_REPORTS,
    },
}


@dataclass
class AuthContext:
    user_id: str
    user_role: UserRole
    user_org_id: Optional[str] = None
    target_org_id: Optional[str] = None
    project_id: Optional[str] = None
    project_owner_id: Optional[str] = None
    environment: str = "development"  # production, staging, development, lab
    is_authorized_for_prod: bool = False
    metadata: dict = field(default_factory=dict)


class AccessControlEngine:
    """Evaluates contextual authorization rules (RBAC + ABAC)."""

    @staticmethod
    def is_authorized(action: Action, context: AuthContext) -> tuple[bool, str]:
        """
        Evaluate if the user is authorized for the given action in this context.
        Returns: (is_allowed, reason)
        """
        # 1. Base RBAC Check
        allowed_actions = ROLE_PERMISSIONS.get(context.user_role, set())
        if action not in allowed_actions:
            return False, f"Role {context.user_role.value} does not have permission for {action.value}"

        # 2. Multi-Tenant Organization Boundary (ABAC)
        if context.user_role != UserRole.ADMIN:
            if context.user_org_id and context.target_org_id:
                if context.user_org_id != context.target_org_id:
                    return False, "Cross-organization access is strictly forbidden."

        # 3. Production Environment Safety Rules (ABAC)
        if context.environment == "production":
            if action in [Action.START_SCAN, Action.RETEST_FINDING]:
                # In production, PENTESTER role requires explicit prod authorization
                if context.user_role == UserRole.PENTESTER and not context.is_authorized_for_prod:
                    return False, "Production scanning requires explicit manager authorization or ADMIN/SECURITY_MANAGER role."

        # 4. Action Approvals (Only Admins and Security Managers can approve high-risk AI actions)
        if action in [Action.APPROVE_AI_ACTION, Action.REJECT_AI_ACTION]:
            if context.user_role not in [UserRole.ADMIN, UserRole.SECURITY_MANAGER]:
                return False, "Only Security Managers and Admins can approve or reject security actions."

        # 5. User Management (Only Admin)
        if action == Action.MANAGE_USERS and context.user_role != UserRole.ADMIN:
            return False, "Only system administrators can manage users."

        return True, "Authorized"
