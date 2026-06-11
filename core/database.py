import aiosqlite
import json
from typing import List, Optional, Dict, Any
from datetime import datetime
from core.models import PortFinding, DatabaseConfig


class Database:
    def __init__(self, config: DatabaseConfig):
        self.path = config.path
        self._conn = None

    async def connect(self):
        import os
        os.makedirs(os.path.dirname(self.path) if os.path.dirname(self.path) else ".", exist_ok=True)
        self._conn = await aiosqlite.connect(self.path)
        await self._conn.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL,
                port INTEGER NOT NULL,
                protocol TEXT DEFAULT 'tcp',
                banner TEXT,
                service TEXT,
                service_version TEXT,
                first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                notified INTEGER DEFAULT 0,
                cves TEXT,
                UNIQUE(ip, port, protocol)
            )
        """)
        await self._conn.execute("""
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                ended_at TIMESTAMP,
                targets TEXT,
                ports TEXT,
                total_found INTEGER DEFAULT 0,
                new_found INTEGER DEFAULT 0
            )
        """)
        await self._conn.commit()

    async def is_new(self, ip: str, port: int, protocol: str = "tcp") -> bool:
        async with self._conn.execute(
            "SELECT 1 FROM findings WHERE ip=? AND port=? AND protocol=?",
            (ip, port, protocol)
        ) as cursor:
            return await cursor.fetchone() is None

    async def save_finding(self, finding: PortFinding) -> bool:
        is_new = await self.is_new(finding.ip, finding.port, finding.protocol)
        cves_json = json.dumps(finding.cves) if finding.cves else "[]"

        if is_new:
            await self._conn.execute(
                """INSERT INTO findings
                   (ip, port, protocol, banner, service, service_version, notified, cves)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (finding.ip, finding.port, finding.protocol, finding.banner,
                 finding.service.value, finding.service_version, 0, cves_json)
            )
        else:
            await self._conn.execute(
                """UPDATE findings
                   SET last_seen=?, banner=?, service=?, service_version=?, cves=?
                   WHERE ip=? AND port=? AND protocol=?""",
                (datetime.utcnow(), finding.banner, finding.service.value,
                 finding.service_version, cves_json, finding.ip, finding.port, finding.protocol)
            )
        await self._conn.commit()
        return is_new

    async def mark_notified(self, ip: str, port: int, protocol: str = "tcp"):
        await self._conn.execute(
            "UPDATE findings SET notified=1 WHERE ip=? AND port=? AND protocol=?",
            (ip, port, protocol)
        )
        await self._conn.commit()

    async def get_recent(self, limit: int = 100) -> List[Dict[str, Any]]:
        async with self._conn.execute(
            """SELECT ip, port, protocol, banner, service, service_version,
                      first_seen, last_seen, notified, cves
               FROM findings ORDER BY last_seen DESC LIMIT ?""",
            (limit,)
        ) as cursor:
            rows = await cursor.fetchall()
            cols = [d[0] for d in cursor.description]
            results = []
            for row in rows:
                row_dict = dict(zip(cols, row))
                cves_raw = row_dict.get("cves")
                try:
                    row_dict["cves"] = json.loads(cves_raw) if cves_raw else []
                except (json.JSONDecodeError, TypeError):
                    row_dict["cves"] = []
                results.append(row_dict)
            return results

    async def get_stats(self) -> Dict[str, Any]:
        async with self._conn.execute("SELECT COUNT(*) FROM findings") as cursor:
            total = (await cursor.fetchone())[0]
        async with self._conn.execute("SELECT COUNT(*) FROM findings WHERE notified=0") as cursor:
            unnotified = (await cursor.fetchone())[0]
        async with self._conn.execute(
            "SELECT service, COUNT(*) FROM findings GROUP BY service"
        ) as cursor:
            services = {row[0]: row[1] for row in await cursor.fetchall()}
        return {"total": total, "unnotified": unnotified, "services": services}

    async def start_scan(self, targets: str, ports: str) -> int:
        cursor = await self._conn.execute(
            "INSERT INTO scan_history (targets, ports) VALUES (?, ?)",
            (targets, ports)
        )
        await self._conn.commit()
        return cursor.lastrowid

    async def end_scan(self, scan_id: int, total: int, new: int):
        await self._conn.execute(
            "UPDATE scan_history SET ended_at=?, total_found=?, new_found=? WHERE id=?",
            (datetime.utcnow(), total, new, scan_id)
        )
        await self._conn.commit()

    async def close(self):
        if self._conn:
            await self._conn.close()