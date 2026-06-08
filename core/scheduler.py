from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger
from core.models import SchedulerConfig


class ScanScheduler:
    def __init__(self, config: SchedulerConfig):
        self.config = config
        self.scheduler = AsyncIOScheduler()

    def start(self, scan_callback):
        if not self.config.enabled:
            return

        self.scheduler.add_job(
            scan_callback,
            trigger=IntervalTrigger(minutes=self.config.interval_minutes),
            id="masscan_scan",
            replace_existing=True
        )
        self.scheduler.start()

    def shutdown(self):
        self.scheduler.shutdown()
