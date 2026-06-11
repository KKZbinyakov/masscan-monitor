# tests/test_scanner.py
import pytest
import tempfile
import os
from core.scanner import MasscanScanner
from core.models import ScanConfig


class TestMasscanScanner:
    """Тесты парсера вывода masscan (без реальных сканов)."""

    def test_parse_item_single_port(self):
        """Парсинг одного порта из JSON-объекта."""
        scanner = MasscanScanner(ScanConfig())
        data = {
            "ip": "192.168.1.1",
            "ports": [{"port": 80, "proto": "tcp", "status": "open", "ttl": 64}]
        }
        findings = scanner._parse_item(data)
        
        assert len(findings) == 1
        assert findings[0].ip == "192.168.1.1"
        assert findings[0].port == 80
        assert findings[0].protocol == "tcp"
        assert findings[0].ttl == 64

    def test_parse_item_multiple_ports(self):
        """Несколько портов на одном IP."""
        scanner = MasscanScanner(ScanConfig())
        data = {
            "ip": "10.0.0.1",
            "ports": [
                {"port": 22, "proto": "tcp"},
                {"port": 80, "proto": "tcp"},
                {"port": 443, "proto": "tcp"}
            ]
        }
        findings = scanner._parse_item(data)
        
        assert len(findings) == 3
        ports = {f.port for f in findings}
        assert ports == {22, 80, 443}

    def test_parse_item_no_ip(self):
        """Объект без IP — пустой результат."""
        scanner = MasscanScanner(ScanConfig())
        data = {"ports": [{"port": 80}]}
        findings = scanner._parse_item(data)
        
        assert findings == []

    def test_parse_item_empty_ports(self):
        """IP без портов — пустой результат."""
        scanner = MasscanScanner(ScanConfig())
        data = {"ip": "192.168.1.1", "ports": []}
        findings = scanner._parse_item(data)
        
        assert findings == []

    def test_parse_output_full_json(self, masscan_json_output):
        """Парсинг полного JSON-массива."""
        scanner = MasscanScanner(ScanConfig())
        
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write(masscan_json_output)
            path = f.name
        
        try:
            findings = scanner._parse_output(path)
            assert len(findings) == 3  # 3 порта total
            
            ips = {f.ip for f in findings}
            assert ips == {"93.184.216.34", "192.0.2.1"}
            
            # Проверяем баннер
            ssh_finding = [f for f in findings if f.port == 22][0]
            assert "SSH-2.0" in ssh_finding.banner
        finally:
            os.unlink(path)

    def test_parse_output_line_by_line(self, masscan_json_line_output):
        """Fallback парсинг построчно."""
        scanner = MasscanScanner(ScanConfig())
        
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write(masscan_json_line_output)
            path = f.name
        
        try:
            findings = scanner._parse_output(path)
            assert len(findings) == 2
            
            mysql = [f for f in findings if f.port == 3306][0]
            assert mysql.banner == "mysql"
        finally:
            os.unlink(path)

    def test_parse_output_with_trailing_comma(self):
        """JSON с запятой перед закрывающей скобкой."""
        scanner = MasscanScanner(ScanConfig())
        content = "[\n{ \"ip\": \"10.0.0.1\", \"ports\": [{\"port\": 80}] },\n]"
        
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write(content)
            path = f.name
        
        try:
            findings = scanner._parse_output(path)
            assert len(findings) == 1
        finally:
            os.unlink(path)

    def test_parse_output_invalid_json_fallback(self):
        """Невалидный JSON — fallback не падает."""
        scanner = MasscanScanner(ScanConfig())
        content = "not json at all"
        
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write(content)
            path = f.name
        
        try:
            findings = scanner._parse_output(path)
            assert findings == []
        finally:
            os.unlink(path)