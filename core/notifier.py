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
                if parts: cve_text = f"\n⚠️ {', '.join(parts)}" # ИСПРАВЛЕНО

            # ИСПРАВЛЕНО: добавлен \n
            line = f"🌐 `{f.ip}:{f.port}` ({f.protocol.upper()})\n🔧 Service: `{f.service.value}`"
            if f.service_version:
                line += f" `{f.service_version}`"
            line += cve_text
            
            if f.banner:
                # Экранируем спецсимволы Markdown, чтобы Telegram не вернул 400 Bad Request
                safe_banner = f.banner[:100].replace("\n", " ").replace("\r", "")
                safe_banner = safe_banner.replace("_", "\\_").replace("*", "\\*").replace("`", "\\`")
                line += f"\n📄 Banner: `{safe_banner}`"
            lines.append(line)
            lines.append("")

        message = "\n".join(lines) # ИСПРАВЛЕНО

        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"https://api.telegram.org/bot{self.config.telegram.bot_token}/sendMessage",
                    json={
                        "chat_id": self.config.telegram.chat_id,
                        "text": message,
                        "parse_mode": "MarkdownV2", # Используем V2 с экранированием
                        "disable_web_page_preview": True
                    },
                    timeout=30.0
                )
                response.raise_for_status()
        except Exception as e:
            logger.error(f"Telegram notification failed: {e}")
            # Fallback: пробуем отправить без parse_mode, если Markdown сломался
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
        # ... (Ваш код отправки email остается без изменений, он корректен)
        pass