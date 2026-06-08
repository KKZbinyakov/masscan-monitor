#!/usr/bin/env python3
"""
Masscan Monitor - Automated network reconnaissance with notifications.

Usage:
    python main.py [--config config.yaml]
"""

import asyncio
import argparse
import yaml
import logging
import shutil
import signal
import sys
from pathlib import Path
from core.models import AppConfig
from core.database import Database
from core.scanner import MasscanScanner
from core.banner_analyzer import BannerAnalyzer
from core.nmap_validator import NmapValidator
from core.cve_checker import VulnersChecker
from core.exploit_checker import ExploitDBChecker
from core.notifier import Notifier
from core.scheduler import ScanScheduler
from web.dashboard import app as dashboard_app, set_db
import uvicorn

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger(__name__)


class MasscanMonitor:
    def __init__(self, config_path: str = "config.yaml"):
        with open(config_path, "r") as f:
            raw_config = yaml.safe_load(f)
        self.config = AppConfig(**raw_config)
        self.db = Database(self.config.database)
        self.scanner = MasscanScanner(self.config.scan)
        self.validator = NmapValidator(
            enabled=self.config.scan.nmap_validation,
            top_ports=self.config.scan.nmap_top_ports
        )
        self.cve_checker = VulnersChecker(self.config.cve)
        self.exploit_checker = ExploitDBChecker(enabled=self.config.exploit_db.enabled)
        self.notifier = Notifier(self.config.notifications)
        self.scheduler = ScanScheduler(self.config.scheduler)
        self._shutdown_event = asyncio.Event()

    def _check_dependencies(self):
        if not shutil.which("masscan"):
            logger.error("masscan not found in PATH. Install: sudo apt-get install masscan")
            sys.exit(1)
        if self.config.scan.nmap_validation and not shutil.which("nmap"):
            logger.warning("nmap not found in PATH. Nmap validation disabled.")
            self.validator.enabled = False
        if self.config.cve.enabled and not self.config.cve.vulners_api_key:
            logger.warning("Vulners API key not configured. CVE checking disabled.")
            self.cve_checker.enabled = False
        if self.config.exploit_db.enabled and not shutil.which("searchsploit"):
            logger.warning("searchsploit not found. Install: sudo apt-get install exploitdb")
            self.exploit_checker.enabled = False

    async def run_scan(self):
        """Execute a single scan cycle."""
        scan_id = await self.db.start_scan(
            targets=",".join(self.config.scan.targets),
            ports=self.config.scan.ports
        )

        try:
            findings = await self.scanner.run()
            new_findings = []
            logger.info(f"Scan complete: {len(findings)} raw findings")

            for finding in findings:
                # 1. Analyze banner for service detection
                finding = BannerAnalyzer.analyze(finding)

                # 2. Optional Nmap validation for version accuracy
                nmap_version = await self.validator.validate(finding)
                if nmap_version:
                    finding.service_version = nmap_version

                # 3. Check CVEs via Vulners API
                finding.cves = await self.cve_checker.check(finding)

                # 4. Check exploit-db for known exploits
                if self.exploit_checker.enabled:
                    exploits = await self.exploit_checker.check(finding)
                    if exploits:
                        finding.cves.extend([{"exploit-db": e} for e in exploits])

                # 5. Persist and check if new
                is_new = await self.db.save_finding(finding)
                finding.is_new = is_new

                if is_new:
                    new_findings.append(finding)
                    logger.info(f"NEW: {finding.ip}:{finding.port} {finding.service.value} {finding.service_version or ''}")

            # 6. Send notifications for new findings
            if new_findings:
                logger.info(f"Sending notifications for {len(new_findings)} new findings")
                await self.notifier.send_notifications(new_findings)
                for f in new_findings:
                    await self.db.mark_notified(f.ip, f.port, f.protocol)

            await self.db.end_scan(scan_id, len(findings), len(new_findings))
            logger.info(f"[SCAN] Complete: {len(findings)} total, {len(new_findings)} new")

        except Exception as e:
            logger.error(f"Scan failed: {e}", exc_info=True)
            await self.db.end_scan(scan_id, 0, 0)
            raise

    async def _scan_loop(self):
        """Periodic scan loop for scheduler mode."""
        while not self._shutdown_event.is_set():
            await self.run_scan()
            try:
                await asyncio.wait_for(self._shutdown_event.wait(), timeout=self.config.scheduler.interval_minutes * 60)
            except asyncio.TimeoutError:
                pass

    async def run(self):
        """Main entry point."""
        self._check_dependencies()
        await self.db.connect()

        if self.config.scheduler.enabled:
            # Start periodic scanning
            self.scheduler.start(self.run_scan)

            # Run initial scan immediately
            await self.run_scan()

            if self.config.dashboard.enabled:
                # Inject DB into dashboard and start web server
                set_db(self.db)
                config = uvicorn.Config(
                    dashboard_app,
                    host=self.config.dashboard.host,
                    port=self.config.dashboard.port,
                    log_level="info"
                )
                server = uvicorn.Server(config)
                await server.serve()
            else:
                # Keep event loop alive with periodic scans
                await self._scan_loop()
        else:
            # Single scan mode
            await self.run_scan()

        await self.db.close()

    def shutdown(self):
        """Graceful shutdown signal handler."""
        logger.info("Shutdown signal received")
        self._shutdown_event.set()
        if self.config.scheduler.enabled:
            self.scheduler.shutdown()


def main():
    parser = argparse.ArgumentParser(description="Masscan Monitor")
    parser.add_argument("--config", default="config.yaml", help="Path to config file")
    args = parser.parse_args()

    monitor = MasscanMonitor(config_path=args.config)

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    # Setup signal handlers for graceful shutdown
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, monitor.shutdown)

    try:
        loop.run_until_complete(monitor.run())
    except KeyboardInterrupt:
        logger.info("Keyboard interrupt received, shutting down...")
    finally:
        monitor.shutdown()
        loop.run_until_complete(monitor.db.close())
        loop.close()


if __name__ == "__main__":
    main()
