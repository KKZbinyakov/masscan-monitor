import pytest
import asyncio
from datetime import datetime
from core.database import Database
from core.models import PortFinding, ServiceType, DatabaseConfig, CVEConfig


class TestDatabase:
    """Тесты БД — полный цикл CRUD на in-memory SQLite."""

    @pytest.fixture
    async def db(self):
        """In-memory БД для каждого теста."""
        database = Database(DatabaseConfig(path=":memory:"))
        await database.connect()
        yield database
        await database.close()

    @pytest.mark.asyncio
    async def test_connect_creates_tables(self, db):
        """После connect таблицы должны существовать."""
        async with db._conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ) as cursor:
            tables = {row[0] for row in await cursor.fetchall()}

        assert "findings" in tables
        assert "scan_history" in tables

    @pytest.mark.asyncio
    async def test_is_new_finding(self, db):
        """Новый finding — is_new=True."""
        is_new = await db.is_new("192.168.1.1", 80, "tcp")
        assert is_new is True

    @pytest.mark.asyncio
    async def test_is_existing_finding(self, db):
        """После сохранения finding больше не новый."""
        finding = PortFinding(ip="192.168.1.1", port=80, protocol="tcp")
        await db.save_finding(finding)

        is_new = await db.is_new("192.168.1.1", 80, "tcp")
        assert is_new is False

    @pytest.mark.asyncio
    async def test_save_finding_returns_is_new(self, db):
        """save_finding возвращает True для новой записи."""
        finding = PortFinding(ip="10.0.0.1", port=22, protocol="tcp")
        result = await db.save_finding(finding)
        assert result is True

    @pytest.mark.asyncio
    async def test_save_finding_updates_existing(self, db):
        """Повторное сохранение обновляет last_seen."""
        finding = PortFinding(
            ip="10.0.0.1", 
            port=22, 
            protocol="tcp",
            banner="SSH-2.0-OpenSSH"
        )
        await db.save_finding(finding)

        finding.banner = "SSH-2.0-OpenSSH_8.0"
        is_new = await db.save_finding(finding)

        assert is_new is False

        recent = await db.get_recent(limit=1)
        assert recent[0]["banner"] == "SSH-2.0-OpenSSH_8.0"

    @pytest.mark.asyncio
    async def test_unique_constraint(self, db):
        """Уникальность по (ip, port, protocol)."""
        finding1 = PortFinding(ip="10.0.0.1", port=80, protocol="tcp")
        finding2 = PortFinding(ip="10.0.0.1", port=80, protocol="tcp")

        await db.save_finding(finding1)
        await db.save_finding(finding2)

        stats = await db.get_stats()
        assert stats["total"] == 1

    @pytest.mark.asyncio
    async def test_mark_notified(self, db):
        """Пометка как уведомлённого."""
        finding = PortFinding(ip="10.0.0.1", port=80)
        await db.save_finding(finding)

        await db.mark_notified("10.0.0.1", 80, "tcp")

        stats = await db.get_stats()
        assert stats["unnotified"] == 0

    @pytest.mark.asyncio
    async def test_get_recent_ordering(self, db):
        """get_recent возвращает в порядке убывания last_seen.

        ВАЖНО: SQLite CURRENT_TIMESTAMP имеет точность до секунды.
        Между вставками нужна пауза >= 1 секунда, иначе порядок непредсказуем.
        """
        f1 = PortFinding(ip="10.0.0.1", port=80)
        f2 = PortFinding(ip="10.0.0.2", port=443)

        await db.save_finding(f1)
        await asyncio.sleep(1.1)  # Гарантируем разницу во времени для SQLite
        await db.save_finding(f2)

        recent = await db.get_recent(limit=10)
        assert len(recent) == 2
        assert recent[0]["ip"] == "10.0.0.2"
        assert recent[1]["ip"] == "10.0.0.1"

    @pytest.mark.asyncio
    async def test_get_recent_limit(self, db):
        """Лимит работает корректно."""
        for i in range(5):
            f = PortFinding(ip=f"10.0.0.{i}", port=80)
            await db.save_finding(f)

        recent = await db.get_recent(limit=3)
        assert len(recent) == 3

    @pytest.mark.asyncio
    async def test_get_recent_cves_deserialization(self, db):
        """CVE должны десериализоваться из JSON."""
        finding = PortFinding(
            ip="10.0.0.1",
            port=80,
            cves=[{"title": "CVE-2021-1234", "cvss": 7.5}]
        )
        await db.save_finding(finding)

        recent = await db.get_recent(limit=1)
        assert recent[0]["cves"] == [{"title": "CVE-2021-1234", "cvss": 7.5}]

    @pytest.mark.asyncio
    async def test_get_stats(self, db):
        """Статистика считается корректно."""
        f1 = PortFinding(ip="10.0.0.1", port=22, service=ServiceType.SSH)
        f2 = PortFinding(ip="10.0.0.2", port=80, service=ServiceType.HTTP)

        await db.save_finding(f1)
        await db.save_finding(f2)

        stats = await db.get_stats()
        assert stats["total"] == 2
        assert stats["unnotified"] == 2
        assert stats["services"]["ssh"] == 1
        assert stats["services"]["http"] == 1

    @pytest.mark.asyncio
    async def test_scan_history(self, db):
        """История сканирований."""
        scan_id = await db.start_scan(targets="10.0.0.0/24", ports="80,443")
        assert isinstance(scan_id, int)

        await db.end_scan(scan_id, total=10, new=5)

        async with db._conn.execute(
            "SELECT total_found, new_found FROM scan_history WHERE id=?",
            (scan_id,)
        ) as cursor:
            row = await cursor.fetchone()
            assert row[0] == 10
            assert row[1] == 5

    @pytest.mark.asyncio
    async def test_cves_json_serialization(self, db):
        """Пустые CVE = '[]' в БД."""
        finding = PortFinding(ip="10.0.0.1", port=80)
        await db.save_finding(finding)

        async with db._conn.execute(
            "SELECT cves FROM findings WHERE ip=? AND port=?",
            ("10.0.0.1", 80)
        ) as cursor:
            row = await cursor.fetchone()
            assert row[0] == "[]"

    @pytest.mark.asyncio
    async def test_close_connection(self):
        """Закрытие соединения."""
        db = Database(DatabaseConfig(path=":memory:"))
        await db.connect()
        await db.close()
        await db.close()  # Повторное закрытие не должно падать