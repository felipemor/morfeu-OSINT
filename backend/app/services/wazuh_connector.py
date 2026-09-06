"""
Wazuh Adapter & Connector for MorfeuXDR Platform
Normalizes raw Wazuh alerts/events into the internal MorfeuEvent structure.
"""
from typing import Dict, Any, Optional
from datetime import datetime, timezone


class MorfeuEvent:
    """Normalized Security Event Structure across providers."""
    def __init__(self, raw_data: Dict[str, Any]):
        rule = raw_data.get("rule", {})
        agent = raw_data.get("agent", {})
        data = raw_data.get("data", {})

        self.event_id = raw_data.get("id", "evt-" + str(raw_data.get("timestamp", "")))
        self.timestamp = raw_data.get("timestamp", datetime.now(timezone.utc).isoformat())
        self.rule_id = str(rule.get("id", "5710"))
        self.rule_level = int(rule.get("level", 5))
        self.rule_description = rule.get("description", "Security Event Detected")
        
        # MITRE Mapping
        mitre = rule.get("mitre", {})
        self.mitre_tactic = mitre.get("tactic", [None])[0] if isinstance(mitre.get("tactic"), list) else mitre.get("tactic")
        self.mitre_technique = mitre.get("id", [None])[0] if isinstance(mitre.get("id"), list) else mitre.get("id")

        # Agent & Host
        self.agent_id = str(agent.get("id", "001"))
        self.hostname = agent.get("name", "ubuntu-prod-01")
        self.agent_ip = agent.get("ip", "10.0.2.15")

        # Process & User Data
        self.username = data.get("dstuser") or data.get("srcuser") or data.get("user", "root")
        self.process = data.get("process") or data.get("system_name") or "sshd"
        self.command_line = data.get("command") or data.get("win", {}).get("eventdata", {}).get("commandLine")

        # Network
        self.src_ip = data.get("srcip") or raw_data.get("srcip")
        self.src_port = data.get("srcport")
        self.dst_ip = data.get("dstip") or raw_data.get("dstip")
        self.dst_port = data.get("dstport")

        self.raw_data = raw_data


class WazuhConnector:
    """Communicates securely with Wazuh API Manager & Event Pipeline."""
    
    @staticmethod
    def normalize_wazuh_alert(alert_json: Dict[str, Any]) -> MorfeuEvent:
        """Converts raw Wazuh JSON payload into MorfeuEvent."""
        return MorfeuEvent(alert_json)
