# tests/test_cve_checker.py
import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from core.cve_checker import VulnersChecker
from core.models import PortFinding, ServiceType, CVEConfig


class TestVulnersChecker:
    """Тесты CVE-чекера: логика определения vendor/product и очистки версий."""

    def test_detect_vendor_product_from_banner(self, cve_config):
        checker = VulnersChecker(cve_config)
        finding = PortFinding(
            ip="10.0.0.1",
            port=80,
            banner="Server: nginx/1.18.0",
            service=ServiceType.HTTP,
            service_version="nginx/1.18.0"
        )
        vendor, product = checker._detect_vendor_product(finding)
        
        assert vendor == "nginx"
        assert product == "nginx"

    def test_detect_vendor_product_apache(self, cve_config):
        checker = VulnersChecker(cve_config)
        finding = PortFinding(
            ip="10.0.0.1",
            port=80,
            banner="Server: Apache/2.4.41",
            service=ServiceType.HTTP
        )
        vendor, product = checker._detect_vendor_product(finding)
        
        assert vendor == "apache"
        assert product == "http_server"

    def test_detect_vendor_product_fallback_to_service(self, cve_config):
        """Если баннер не распознан — fallback по типу сервиса."""
        checker = VulnersChecker(cve_config)
        finding = PortFinding(
            ip="10.0.0.1",
            port=22,
            banner="",
            service=ServiceType.SSH
        )
        vendor, product = checker._detect_vendor_product(finding)
        
        assert vendor == "openbsd"
        assert product == "openssh"

    def test_detect_vendor_product_unknown_service(self, cve_config):
        """Неизвестный сервис — возвращаем generic."""
        checker = VulnersChecker(cve_config)
        finding = PortFinding(
            ip="10.0.0.1",
            port=9999,
            service=ServiceType.UNKNOWN
        )
        vendor, product = checker._detect_vendor_product(finding)
        
        assert vendor == "unknown"
        assert product == "unknown"

    def test_clean_version_simple(self, cve_config):
        checker = VulnersChecker(cve_config)
        assert checker._clean_version("2.4.41") == "2.4.41"

    def test_clean_version_with_prefix(self, cve_config):
        """Apache/2.4.41 → 2.4.41."""
        checker = VulnersChecker(cve_config)
        assert checker._clean_version("Apache/2.4.41") == "2.4.41"

    def test_clean_version_openssh(self, cve_config):
        """OpenSSH_8.2p1 Ubuntu-4ubuntu0.5 → 8.2."""
        checker = VulnersChecker(cve_config)
        result = checker._clean_version("OpenSSH_8.2p1")
        assert result == "8.2"

    def test_clean_version_empty(self, cve_config):
        checker = VulnersChecker(cve_config)
        assert checker._clean_version("") == ""
        assert checker._clean_version(None) == ""

    def test_clean_version_no_numbers(self, cve_config):
        checker = VulnersChecker(cve_config)
        assert checker._clean_version("unknown") == "unknown"

    def test_disabled_checker_returns_empty(self):
        """Отключенный чекер всегда возвращает []."""
        config = CVEConfig(enabled=False)
        checker = VulnersChecker(config)
        finding = PortFinding(ip="10.0.0.1", port=80)
        
        # Нельзя await в sync тесте, но можно проверить логику напрямую
        assert checker.enabled is False

    def test_no_api_key_disables_checker(self):
        """Без ключа — чекер логически отключен."""
        config = CVEConfig(enabled=True, vulners_api_key=None)
        checker = VulnersChecker(config)
        assert not checker.api_key  # Пустой ключ

    @pytest.mark.asyncio
    async def test_check_returns_empty_when_disabled(self):
        """Async тест: отключенный чекер возвращает пустой список."""
        config = CVEConfig(enabled=False)
        checker = VulnersChecker(config)
        finding = PortFinding(ip="10.0.0.1", port=80, service_version="1.0")
        
        result = await checker.check(finding)
        assert result == []

    @pytest.mark.asyncio
    async def test_check_returns_empty_without_version(self, cve_config):
        """Без версии нечего проверять."""
        checker = VulnersChecker(cve_config)
        finding = PortFinding(ip="10.0.0.1", port=80)  # Нет service_version
        
        result = await checker.check(finding)
        assert result == []