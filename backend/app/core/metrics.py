"""
Prometheus Observability Metrics — Operational and AI Reasoning Metrics
"""
from prometheus_client import Counter, Gauge, Histogram

# ─── Operational Metrics ──────────────────────────────────────────────────────
SCANS_TOTAL = Counter("pentest_scans_total", "Total pentest scans initiated", ["mode", "status"])
SCANS_ACTIVE = Gauge("pentest_scans_active", "Currently running pentest scans")
SCAN_DURATION = Histogram("pentest_scan_duration_seconds", "Duration of pentest scans in seconds")

ASSETS_DISCOVERED = Counter("pentest_assets_discovered_total", "Total assets discovered by recon", ["asset_type"])
ENDPOINTS_DISCOVERED = Counter("pentest_endpoints_discovered_total", "Total endpoints discovered", ["is_api"])

REQUESTS_EXECUTED = Counter("pentest_requests_executed_total", "HTTP and Browser requests executed", ["agent_type", "method"])
REQUESTS_BLOCKED = Counter("pentest_requests_blocked_total", "Requests blocked by Policy Engine or Interceptor", ["rule"])
SCOPE_VIOLATIONS = Counter("pentest_scope_violations_total", "Scope violations intercepted before request", ["target_type"])
AGENT_FAILURES = Counter("pentest_agent_failures_total", "Failures encountered during agent execution", ["agent_type"])

FINDINGS_TOTAL = Counter("pentest_findings_total", "Total findings discovered", ["severity"])
CONFIRMED_FINDINGS = Counter("pentest_findings_confirmed_total", "Findings confirmed after validation", ["severity"])
FALSE_POSITIVES = Counter("pentest_false_positives_total", "Findings flagged as false positives")

# ─── AI Reasoning Metrics ─────────────────────────────────────────────────────
AI_HYPOTHESES_TOTAL = Counter("pentest_ai_hypotheses_total", "Total AI hypotheses generated", ["test_type", "priority"])
AI_HYPOTHESES_ACCEPTED = Counter("pentest_ai_hypotheses_accepted_total", "AI hypotheses approved for execution")
AI_HYPOTHESES_REJECTED = Counter("pentest_ai_hypotheses_rejected_total", "AI hypotheses rejected by policy or human")
AI_HUMAN_APPROVALS = Counter("pentest_ai_human_approvals_total", "Human approvals processed", ["decision"])
