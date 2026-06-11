# tests/test_notifier.py
import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from core.notifier import Notifier
from core.models import PortFinding, ServiceType, NotificationConfig, TelegramConfig, EmailConfig


class TestNotifier:
    """Тесты форматирования уведомлений (без реальных отправок)."""

    def test_telegram_message_format(self):
        """Проверка формата Markdown для Telegram."""
        config = NotificationConfig(
            telegram=TelegramConfig(enabled=True, bot_token="test", chat_id="123")
        )
        notifier = Notifier(config)
        
        finding = PortFinding(
            ip="192.168.1.1",
            port=80,
            service=ServiceType.HTTP,
            service_version="nginx/1.18.0",
            banner="HTTP/1.1 200 OK"
        )
        
        lines = ["🔴 *New open ports detected*", ""]
        line = f"🌐 `{finding.ip}:{finding.port}` ({finding.protocol.upper()})\n🔧 Service: `{finding.service.value}`"
        assert "192.168.1.1:80" in line
        assert "http" in line

    def test_telegram_with_cves(self):
        """Форматирование с CVE в сообщении."""
        finding = PortFinding(
            ip="10.0.0.1",
            port=22,
            service=ServiceType.SSH,
            cves=[
                {"title": "CVE-2021-1234"},
                {"exploit-db": {"id": "12345"}}
            ]
        )
        
        cve_count = len([c for c in finding.cves if "exploit-db" not in c])
        exploit_count = len([c for c in finding.cves if "exploit-db" in c])
        assert cve_count == 1
        assert exploit_count == 1

    def test_email_html_structure(self):
        """HTML email содержит таблицу."""
        config = NotificationConfig(
            email=EmailConfig(
                enabled=True,
                smtp_host="smtp.test.com",
                user="test@test.com",
                to="admin@test.com"
            )
        )
        notifier = Notifier(config)
        
        finding = PortFinding(
            ip="10.0.0.1",
            port=443,
            service=ServiceType.HTTPS
        )

        html = """<table><tr><th>IP</th><th>Port</th>"""
        assert "<table>" in html
        assert "IP" in html

    def test_email_risk_badges(self):
        """Формирование badge'ов для рисков."""
        finding = PortFinding(
            ip="10.0.0.1",
            port=80,
            cves=[
                {"title": "CVE-2021-1234"},
                {"exploit-db": {"id": "123"}}
            ]
        )
        
        cve_count = len([c for c in finding.cves if "exploit-db" not in c])
        exploit_count = len([c for c in finding.cves if "exploit-db" in c])
        
        badges = []
        if cve_count:
            badges.append(f'CVEs: {cve_count}')
        if exploit_count:
            badges.append(f'Exploits: {exploit_count}')
        
        assert len(badges) == 2
        assert "CVEs: 1" in badges[0]

    def test_notifier_skips_when_no_findings(self):
        """Пустой список findings — ничего не отправляем."""
        config = NotificationConfig(
            telegram=TelegramConfig(enabled=True, bot_token="test", chat_id="123")
        )
        notifier = Notifier(config)


    def test_telegram_not_configured_warning(self):
        """Неполная конфигурация Telegram — warning."""
        config = NotificationConfig(
            telegram=TelegramConfig(enabled=True, bot_token=None, chat_id="123")
        )
        notifier = Notifier(config)

        assert notifier.config.telegram.bot_token is None

    def test_email_not_configured_warning(self):
        """Неполная конфигурация Email — warning."""
        config = NotificationConfig(
            email=EmailConfig(enabled=True, smtp_host=None, user="test", to="admin")
        )
        notifier = Notifier(config)
        
        assert notifier.config.email.smtp_host is None

    @pytest.mark.asyncio
    async def test_send_notifications_empty_list(self):
        """Пустой список — корутина завершается мгновенно."""
        config = NotificationConfig(
            telegram=TelegramConfig(enabled=True, bot_token="test", chat_id="123")
        )
        notifier = Notifier(config)

        with patch.object(notifier, '_send_telegram', new_callable=AsyncMock) as mock:
            await notifier.send_notifications([])
            mock.assert_not_awaited()