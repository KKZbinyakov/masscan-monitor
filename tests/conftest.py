# tests/conftest.py
import pytest
import tempfile
import os
from datetime import datetime
from core.models import (
    PortFinding, ScanConfig, NotificationConfig, CVEConfig,
    ExploitDBConfig, SchedulerConfig, DashboardConfig, DatabaseConfig,
    AppConfig, ServiceType
)


@pytest.fixture
def sample_finding():
    """Базовый finding для тестов."""
    return PortFinding(
        ip="192.168.1.1",
        port=80,
        banner="HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n\r\n"
    )


@pytest.fixture
def ssh_finding():
    return PortFinding(
        ip="10.0.0.1",
        port=22,
        banner="SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n"
    )


@pytest.fixture
def ftp_finding():
    return PortFinding(
        ip="10.0.0.2",
        port=21,
        banner="220 Welcome to FileZilla Server 0.9.60 beta\r\n"
    )


@pytest.fixture
def temp_db_path():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        path = f.name
    yield path
    if os.path.exists(path):
        os.unlink(path)


@pytest.fixture
async def db_instance(temp_db_path):
    from core.database import Database
    db = Database(DatabaseConfig(path=temp_db_path))
    await db.connect()
    yield db
    await db.close()


@pytest.fixture
def scan_config():
    return ScanConfig(
        targets=["127.0.0.1/32"],
        ports="80,443",
        rate=100,
        retries=1,
        wait=1
    )


@pytest.fixture
def app_config(scan_config):
    return AppConfig(
        scan=scan_config,
        notifications=NotificationConfig(),
        cve=CVEConfig(enabled=False),
        exploit_db=ExploitDBConfig(enabled=False),
        scheduler=SchedulerConfig(enabled=False),
        dashboard=DashboardConfig(enabled=False),
        database=DatabaseConfig(path=":memory:")
    )


@pytest.fixture
def masscan_json_output():
    """Пример реального вывода masscan -oJ."""
    return """[
{   "ip": "93.184.216.34",   "timestamp": "1718000000", "ports": [ {"port": 80, "proto": "tcp", "status": "open", "reason": "syn-ack", "ttl": 64, "banner": "HTTP/1.1 200 OK"} ] },
{   "ip": "93.184.216.34",   "timestamp": "1718000001", "ports": [ {"port": 443, "proto": "tcp", "status": "open", "reason": "syn-ack", "ttl": 64} ] },
{   "ip": "192.0.2.1",      "timestamp": "1718000002", "ports": [ {"port": 22, "proto": "tcp", "status": "open", "reason": "syn-ack", "ttl": 55, "banner": "SSH-2.0-OpenSSH_8.0"} ] }
]
"""


@pytest.fixture
def masscan_json_line_output():
    """Вывод masscan построчно (старый формат)."""
    return """[
{ "ip": "10.0.0.1", "ports": [{"port": 8080, "proto": "tcp", "status": "open"}] },
{ "ip": "10.0.0.2", "ports": [{"port": 3306, "proto": "tcp", "status": "open", "banner": "mysql"}] },
]
"""


@pytest.fixture
def nmap_xml_single():
    """XML вывод nmap для одного хоста/порта."""
    return """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun>
  <host>
    <address addr="192.168.1.1" addrtype="ipv4"/>
    <ports>
      <port portid="80">
        <service name="http" product="Apache httpd" version="2.4.41"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


@pytest.fixture
def nmap_xml_batch():
    """XML вывод nmap для нескольких хостов."""
    return """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun>
  <host>
    <address addr="10.0.0.1" addrtype="ipv4"/>
    <ports>
      <port portid="22"><service name="ssh" product="OpenSSH" version="8.2p1"/></port>
      <port portid="80"><service name="http" product="nginx" version="1.18.0"/></port>
    </ports>
  </host>
  <host>
    <address addr="10.0.0.2" addrtype="ipv4"/>
    <ports>
      <port portid="443"><service name="https" product="Apache httpd" version="2.4.41"/></port>
    </ports>
  </host>
</nmaprun>
"""


@pytest.fixture
def nmap_xml_no_version():
    """XML без версии (только product)."""
    return """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun>
  <host>
    <address addr="192.168.1.1" addrtype="ipv4"/>
    <ports>
      <port portid="25">
        <service name="smtp" product="Postfix"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


@pytest.fixture
def cve_config():
    return CVEConfig(enabled=True, vulners_api_key="test-key-123")


@pytest.fixture
def notification_config():
    return NotificationConfig()