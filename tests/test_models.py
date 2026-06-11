import pytest
from pydantic import ValidationError
from core.models import (
    PortFinding, ScanConfig, AppConfig, ServiceType,
    NotificationConfig, CVEConfig, DatabaseConfig
)


class TestModels:
    """Тесты Pydantic-моделей — валидация и дефолты."""

    def test_port_finding_defaults(self):
        """Проверка дефолтных значений PortFinding."""
        finding = PortFinding(ip="192.168.1.1", port=80)

        assert finding.protocol == "tcp"
        assert finding.status == "open"
        assert finding.service == ServiceType.UNKNOWN
        assert finding.is_new is True
        assert finding.cves == []

    def test_port_finding_invalid_ip_rejected(self):
        """Невалидный IP отклоняется валидацией."""
        with pytest.raises(ValidationError):
            PortFinding(ip="not-an-ip", port=80)

    def test_port_finding_port_too_low_rejected(self):
        """Порт < 1 отклоняется."""
        with pytest.raises(ValidationError):
            PortFinding(ip="192.168.1.1", port=0)

    def test_port_finding_port_too_high_rejected(self):
        """Порт > 65535 отклоняется."""
        with pytest.raises(ValidationError):
            PortFinding(ip="192.168.1.1", port=70000)

    def test_port_finding_valid_boundary_ports(self):
        """Граничные значения портов проходят."""
        f_min = PortFinding(ip="192.168.1.1", port=1)
        f_max = PortFinding(ip="192.168.1.1", port=65535)

        assert f_min.port == 1
        assert f_max.port == 65535

    def test_service_type_enum_values(self):
        """Все ожидаемые сервисы присутствуют."""
        expected = {"ssh", "http", "https", "ftp", "smtp", "mysql", 
                    "postgresql", "telnet", "rdp", "vnc", "unknown"}
        actual = {s.value for s in ServiceType}
        assert actual == expected

    def test_scan_config_defaults(self):
        config = ScanConfig()

        assert config.ports == "1-1024"
        assert config.rate == 1000
        assert config.banners is True
        assert config.retries == 2
        assert config.nmap_validation is False

    def test_app_config_nested_defaults(self):
        """Проверка вложенных дефолтов в AppConfig."""
        raw = {
            "scan": {"targets": ["127.0.0.1"]},
            "notifications": {},
            "cve": {"enabled": False},
            "scheduler": {"enabled": False},
            "dashboard": {"enabled": False},
            "database": {}
        }
        config = AppConfig(**raw)

        assert config.scan.rate == 1000
        assert config.database.path == "data/findings.db"
        assert config.notifications.telegram.enabled is False

    def test_notification_config_validation(self):
        """EmailConfig с невалидным портом."""
        from core.models import EmailConfig
        with pytest.raises(ValidationError):
            EmailConfig(smtp_port="not-a-number")