import asyncio
import httpx
import logging
import html
from typing import List
from aiosmtplib import SMTP
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from core.models import PortFinding, NotificationConfig

logger = logging.getLogger(__name__)

class Notifier:
    def __init__(self, config: NotificationConfig):
        self.config = config

    async def send_notifications(self, findings: List[PortFinding]):
        if not findings: return
        tasks = []
        if self.config.telegram.enabled: tasks.append(self._send_telegram(findings))
        if self.config.email.enabled: tasks.append(self._send_email(findings))
        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for i, result in enumerate(results):
                if isinstance(result, Exception):
                    logger.error(f"Notification channel {i} failed: {result}")

    async def _send_telegram(self, findings: List[PortFinding]):
        if not self.config.telegram.bot_token or not self.config.telegram.chat_id:
            logger.warning("Telegram not configured")
            return

        lines = ["🔴 *New open ports detected*", ""]
        for f in findings:
            cve_text = ""
            if f.cves:
                cve_count = len([c for c in f.cves if "exploit-db" not in c])
                exploit_count = len([c for c in f.cves if "exploit-db" in c])
                parts = []
                if cve_count: parts.append(f"CVEs: {cve_count}")
                if exploit_count: parts.append(f"Exploits: {exploit_count}")
                if parts: cve_text = f"\n⚠️ {', '.join(parts)}"

            line = f"🌐 `{f.ip}:{f.port}` ({f.protocol.upper()})\n🔧 Service: `{f.service.value}`"
            if f.service_version:
                line += f" `{f.service_version}`"
            line += cve_text
            
            if f.banner:
                safe_banner = f.banner[:100].replace("\n", " ").replace("\r", "")
                safe_banner = safe_banner.replace("_", "\\_").replace("*", "\\*").replace("`", "\\`")
                line += f"\n📄 Banner: `{safe_banner}`"
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
                        "parse_mode": "MarkdownV2",
                        "disable_web_page_preview": True
                    },
                    timeout=30.0
                )
                response.raise_for_status()
        except Exception as e:
            logger.error(f"Telegram notification failed: {e}")
            try:
                async with httpx.AsyncClient() as client:
                    await client.post(
                        f"https://api.telegram.org/bot{self.config.telegram.bot_token}/sendMessage",
                        json={"chat_id": self.config.telegram.chat_id, "text": message},
                        timeout=30.0
                    )
            except Exception:
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

        html = """<html><body><h2>🔴 New Open Ports Detected</h2><table border="1" cellpadding="5">"""
        html += "<tr><th>IP</th><th>Port</th><th>Protocol</th><th>Service</th><th>Version</th><th>Banner</th><th>Risk</th></tr>"

        for f in findings:
            cve_count = len([c for c in f.cves if "exploit-db" not in c])
            exploit_count = len([c for c in f.cves if "exploit-db" in c])
            risk_badges = []
            if cve_count:
                risk_badges.append(f'<span style="color:red">CVEs: {cve_count}</span>')
            if exploit_count:
                risk_badges.append(f'<span style="color:orange">Exploits: {exploit_count}</span>')
            risk_html = " ".join(risk_badges) if risk_badges else "None"

            banner = (f.banner or "N/A")[:120].replace("<", "&lt;").replace(">", "&gt;")
            html += (
                f"<tr>"
                f"<td><b>{f.ip}</b></td>"
                f"<td>{f.port}</td>"
                f"<td>{f.protocol.upper()}</td>"
                f"<td>{f.service.value}</td>"
                f"<td>{f.service_version or 'N/A'}</td>"
                f"<td>{banner}</td>"
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