import asyncio
import httpx
import logging
from typing import List
from aiosmtplib import SMTP
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from core.models import PortFinding, NotificationConfig

logger = logging.getLogger(__name__)


class Notifier:
    """Sends notifications via Telegram and Email."""

    def __init__(self, config: NotificationConfig):
        self.config = config

    async def send_notifications(self, findings: List[PortFinding]):
        if not findings:
            return

        tasks = []
        if self.config.telegram.enabled:
            tasks.append(self._send_telegram(findings))
        if self.config.email.enabled:
            tasks.append(self._send_email(findings))

        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for i, result in enumerate(results):
                if isinstance(result, Exception):
                    logger.error(f"Notification channel {i} failed: {result}")

    async def _send_telegram(self, findings: List[PortFinding]):
        if not self.config.telegram.bot_token or not self.config.telegram.chat_id:
            logger.warning("Telegram not configured: missing bot_token or chat_id")
            return

        lines = ["🔴 *New open ports detected*", ""]
        for f in findings:
            cve_text = ""
            if f.cves:
                cve_count = len([c for c in f.cves if "exploit-db" not in c])
                exploit_count = len([c for c in f.cves if "exploit-db" in c])
                parts = []
                if cve_count:
                    parts.append(f"CVEs: {cve_count}")
                if exploit_count:
                    parts.append(f"Exploits: {exploit_count}")
                if parts:
                    cve_text = f"\n⚠️ {', '.join(parts)}"

            line = f"🌐 `{f.ip}:{f.port}` ({f.protocol.upper()})\n🔧 Service: `{f.service.value}`"
            if f.service_version:
                line += f" `{f.service_version}`"
            line += cve_text
            if f.banner:
                banner = f.banner[:100].replace("\n", " ").replace("\r", "")
                line += f"\n📄 Banner: `{banner}`"
            lines.append(line)
            lines.append("")

        message = "\n".join(lines)

        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"https://api.telegram.org/bot{self.config.telegram.bot_token}/sendMessage",
                    json={
                        "chat_id": self.config.telegram.chat_id,
                        "text": message,
                        "parse_mode": "Markdown",
                        "disable_web_page_preview": True
                    },
                    timeout=30.0
                )
                response.raise_for_status()
                logger.info(f"Telegram notification sent to {self.config.telegram.chat_id}")
        except Exception as e:
            logger.error(f"Telegram notification failed: {e}")
            raise

    async def _send_email(self, findings: List[PortFinding]):
        cfg = self.config.email
        if not cfg.smtp_host or not cfg.user or not cfg.to:
            logger.warning("Email not configured: missing smtp_host, user or to")
            return

        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"[Masscan Monitor] {len(findings)} new open ports detected"
        msg["From"] = cfg.user
        msg["To"] = cfg.to

        # Build HTML table
        html = """<html><head><style>
            body { font-family: Arial, sans-serif; background: #f5f5f5; padding: 20px; }
            h2 { color: #d32f2f; }
            table { width: 100%; border-collapse: collapse; background: white; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
            th { background: #2196F3; color: white; padding: 12px; text-align: left; font-size: 13px; text-transform: uppercase; }
            td { padding: 12px; border-bottom: 1px solid #e0e0e0; font-size: 14px; }
            tr:hover { background: #f5f5f5; }
            .badge { display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 12px; font-weight: bold; }
            .badge-cve { background: #ffebee; color: #c62828; }
            .badge-exploit { background: #fff3e0; color: #ef6c00; }
            .banner { font-family: monospace; font-size: 12px; color: #666; max-width: 300px; word-break: break-all; }
        </style></head><body>"""
        html += "<h2>🔴 New Open Ports Detected</h2>"
        html += "<table><tr><th>IP</th><th>Port</th><th>Protocol</th><th>Service</th><th>Version</th><th>Banner</th><th>Risk</th></tr>"

        for f in findings:
            cve_count = len([c for c in f.cves if "exploit-db" not in c])
            exploit_count = len([c for c in f.cves if "exploit-db" in c])
            risk_badges = []
            if cve_count:
                risk_badges.append(f'<span class="badge badge-cve">CVEs: {cve_count}</span>')
            if exploit_count:
                risk_badges.append(f'<span class="badge badge-exploit">Exploits: {exploit_count}</span>')
            risk_html = " ".join(risk_badges) if risk_badges else "<span style='color:#999'>None</span>"

            banner = (f.banner or "N/A")[:120].replace("<", "&lt;").replace(">", "&gt;")
            html += (
                f"<tr>"
                f"<td><strong>{f.ip}</strong></td>"
                f"<td>{f.port}</td>"
                f"<td>{f.protocol.upper()}</td>"
                f"<td>{f.service.value}</td>"
                f"<td>{f.service_version or 'N/A'}</td>"
                f"<td class='banner'>{banner}</td>"
                f"<td>{risk_html}</td>"
                f"</tr>"
            )

        html += "</table></body></html>"
        msg.attach(MIMEText(html, "html"))

        try:
            smtp = SMTP(
                hostname=cfg.smtp_host,
                port=cfg.smtp_port,
                use_tls=cfg.use_tls
            )
            await smtp.connect()
            if cfg.use_tls:
                await smtp.starttls()
            await smtp.login(cfg.user, cfg.password)
            await smtp.send_message(msg)
            await smtp.quit()
            logger.info(f"Email notification sent to {cfg.to}")
        except Exception as e:
            logger.error(f"Email notification failed: {e}")
            raise
