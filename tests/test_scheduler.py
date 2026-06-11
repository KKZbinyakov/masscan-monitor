import pytest
import asyncio
from unittest.mock import MagicMock
from core.scheduler import ScanScheduler
from core.models import SchedulerConfig


class TestScanScheduler:
    """Тесты планировщика."""

    def test_disabled_scheduler(self):
        """Отключенный scheduler не создаёт задачи."""
        config = SchedulerConfig(enabled=False)
        scheduler = ScanScheduler(config)

        callback = MagicMock()
        scheduler.start(callback)

        assert not scheduler.scheduler.running

    @pytest.mark.asyncio
    async def test_enabled_scheduler_adds_job(self):
        """Включенный scheduler добавляет job."""
        config = SchedulerConfig(enabled=True, interval_minutes=30)
        scheduler = ScanScheduler(config)

        callback = MagicMock()
        scheduler.start(callback)

        jobs = scheduler.scheduler.get_jobs()
        assert len(jobs) == 1
        assert jobs[0].id == "masscan_scan"

        scheduler.shutdown()

    @pytest.mark.asyncio
    async def test_scheduler_interval(self):
        """Проверка интервала."""
        config = SchedulerConfig(enabled=True, interval_minutes=60)
        scheduler = ScanScheduler(config)

        callback = MagicMock()
        scheduler.start(callback)

        job = scheduler.scheduler.get_job("masscan_scan")
        assert job.trigger.interval.total_seconds() == 3600

        scheduler.shutdown()
