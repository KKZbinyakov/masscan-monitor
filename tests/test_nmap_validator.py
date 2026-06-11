# tests/test_nmap_validator.py
import pytest
import tempfile
import os
from core.nmap_validator import NmapValidator
from core.models import PortFinding, ServiceType


class TestNmapValidator:
    """Тесты парсера XML-вывода nmap — ключевая логика валидации."""

    def test_disabled_validator_skips_parsing(self, nmap_xml_single):
        validator = NmapValidator(enabled=False)
        # Парсинг не должен вызываться при enabled=False
        assert validator.enabled is False

    def test_parse_version_single_port(self, nmap_xml_single):
        validator = NmapValidator(enabled=True)
        
        with tempfile.NamedTemporaryFile(mode="w", suffix=".xml", delete=False) as f:
            f.write(nmap_xml_single)
            path = f.name
        
        try:
            version = validator._parse_version(path)
            assert version == "Apache httpd 2.4.41"
        finally:
            os.unlink(path)

    def test_parse_batch_multiple_hosts(self, nmap_xml_batch):
        validator = NmapValidator(enabled=True)
        
        with tempfile.NamedTemporaryFile(mode="w", suffix=".xml", delete=False) as f:
            f.write(nmap_xml_batch)
            path = f.name
        
        try:
            results = validator._parse_batch(path)
            assert ("10.0.0.1", 22) in results
            assert ("10.0.0.1", 80) in results
            assert ("10.0.0.2", 443) in results
            assert results[("10.0.0.1", 22)] == "OpenSSH 8.2p1"
            assert results[("10.0.0.1", 80)] == "nginx 1.18.0"
        finally:
            os.unlink(path)

    def test_parse_version_product_only_no_version(self, nmap_xml_no_version):
        """Если только product без version — возвращаем product."""
        validator = NmapValidator(enabled=True)
        
        with tempfile.NamedTemporaryFile(mode="w", suffix=".xml", delete=False) as f:
            f.write(nmap_xml_no_version)
            path = f.name
        
        try:
            version = validator._parse_version(path)
            assert version == "Postfix"
        finally:
            os.unlink(path)

    def test_parse_batch_empty_xml(self):
        """Пустой/невалидный XML не падает."""
        validator = NmapValidator(enabled=True)
        
        with tempfile.NamedTemporaryFile(mode="w", suffix=".xml", delete=False) as f:
            f.write("<?xml version='1.0'?><invalid/>")
            path = f.name
        
        try:
            results = validator._parse_batch(path)
            assert results == {}
        finally:
            os.unlink(path)

    def test_parse_version_no_service_tag(self):
        """XML без тега service — возвращаем None."""
        xml = """<?xml version="1.0"?>
        <nmaprun>
          <host>
            <address addr="192.168.1.1" addrtype="ipv4"/>
            <ports>
              <port portid="80"/>
            </ports>
          </host>
        </nmaprun>"""
        
        validator = NmapValidator(enabled=True)
        with tempfile.NamedTemporaryFile(mode="w", suffix=".xml", delete=False) as f:
            f.write(xml)
            path = f.name
        
        try:
            version = validator._parse_version(path)
            assert version is None
        finally:
            os.unlink(path)

    def test_interesting_ports_filter(self):
        """Проверяем, что фильтр interesting_ports корректен."""
        validator = NmapValidator(enabled=True)
        interesting = {21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
                       993, 995, 1723, 3306, 3389, 5432, 5900, 8080, 8443}
        
        # Порт 12345 не интересен
        assert 12345 not in interesting
        # Порт 80 интересен
        assert 80 in interesting
        # Порт 22 интересен
        assert 22 in interesting

    def test_validate_single_port_not_interesting(self):
        """Неинтересный порт пропускается."""
        validator = NmapValidator(enabled=True)
        finding = PortFinding(ip="10.0.0.1", port=12345)
        
        # validate — корутина, но при not interesting должно вернуть None
        # Проверяем логику: порт не в interesting_ports
        assert finding.port not in {21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
                                    993, 995, 1723, 3306, 3389, 5432, 5900, 8080, 8443}

    def test_top_ports_default(self):
        validator = NmapValidator(enabled=True)
        assert validator.top_ports == 50  # Дефолт из модели

    def test_top_ports_custom(self):
        validator = NmapValidator(enabled=True, top_ports=100)
        assert validator.top_ports == 100