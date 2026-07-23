"""
Nexus AI — Database Seeding
"""
from datetime import datetime
from sqlalchemy import select
from database import AsyncSessionLocal, User, Threat, ServerNode
from auth_utils import get_password_hash


async def seed_database():
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User).where(User.email == "admin@nexusai.com"))
        if result.scalar_one_or_none():
            return

        admin = User(
            email="admin@nexusai.com",
            password_hash=get_password_hash("admin123"),
            full_name="Admin User",
            role="Senior SOC Security Analyst",
            created_at=datetime.utcnow()
        )
        session.add(admin)
        await session.flush()

        demo_threats = [
            Threat(
                log_id=None,
                severity="Critical",
                time="2026-07-22 04:15:10",
                server="Database-Cluster",
                category="Data Exfiltration",
                ip="192.168.1.104",
                summary="A database dump command was executed immediately following a brute force SSH entry.",
                raw="2026-07-22 04:15:10 Database-Cluster mysqldump: Dumped table users_audit to /tmp/dump.sql",
                ai_analysis=None,
                confidence=0.94,
                detected_at=datetime.utcnow()
            ),
            Threat(
                log_id=None,
                severity="Critical",
                time="2026-07-22 03:45:00",
                server="Web-Server-01",
                category="SSH Brute Force",
                ip="192.168.1.104",
                summary="15,420 failed login attempts detected within a 2-hour window.",
                raw="2026-07-22 03:45:00 Web-Server-01 sshd[4012]: Failed password for invalid user root from 192.168.1.104",
                ai_analysis=None,
                confidence=0.98,
                detected_at=datetime.utcnow()
            ),
            Threat(
                log_id=None,
                severity="High",
                time="2026-07-22 02:10:33",
                server="Firewall-Main",
                category="Port Scanning",
                ip="45.142.214.12",
                summary="Sequential SYN packets detected across 1,024 closed ports.",
                raw="2026-07-22 02:10:33 Firewall-Main kernel: [BLOCK] IN=eth0 OUT= SRC=45.142.214.12 PROTO=TCP SYN",
                ai_analysis=None,
                confidence=0.87,
                detected_at=datetime.utcnow()
            ),
            Threat(
                log_id=None,
                severity="Medium",
                time="2026-07-22 01:05:12",
                server="Web-Server-01",
                category="SQL Injection",
                ip="185.220.101.5",
                summary="HTTP GET request contained malformed SQL payload in URL parameters.",
                raw="2026-07-22 01:05:12 Web-Server-01 nginx: GET /api/user?id=1%20OR%201=1 HTTP/1.1 400",
                ai_analysis=None,
                confidence=0.91,
                detected_at=datetime.utcnow()
            )
        ]
        session.add_all(demo_threats)

        demo_servers = [
            ServerNode(
                name="Firewall-Main",
                ip="10.0.0.1",
                type="Cisco ASA",
                status="online",
                rate="240 logs/sec",
                total_today="1.2M",
                api_token=None,
                last_seen=datetime.utcnow()
            ),
            ServerNode(
                name="Web-Server-01",
                ip="192.168.1.104",
                type="Ubuntu 22.04",
                status="online",
                rate="85 logs/sec",
                total_today="420K",
                api_token=None,
                last_seen=datetime.utcnow()
            ),
            ServerNode(
                name="Database-Cluster",
                ip="192.168.1.200",
                type="PostgreSQL Linux",
                status="warning",
                rate="12 logs/sec",
                total_today="95K",
                api_token=None,
                last_seen=datetime.utcnow()
            ),
            ServerNode(
                name="Auth-Server-02",
                ip="192.168.1.105",
                type="Windows Server 2022",
                status="online",
                rate="45 logs/sec",
                total_today="180K",
                api_token=None,
                last_seen=datetime.utcnow()
            )
        ]
        session.add_all(demo_servers)

        await session.commit()
        print("[Seed] Database seeded with demo data.")
