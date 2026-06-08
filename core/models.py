from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime
from enum import Enum


class ServiceType(str, Enum):
    SSH = "ssh"
    HTTP = "http"
    HTTPS = "https"
    FTP = "ftp"
    SMTP = "smtp"
    MYSQL = "mysql"
    POSTGRESQL = "postgresql"
    TELNET = "telnet"
    RDP = "rdp"
    VNC = "vnc"
    UNKNOWN = "unknown"


class PortFinding(BaseModel):
    ip: str
    port: int
    protocol: str = "tcp"
    status: str = "open"
    reason: Optional[str] = None
    ttl: Optional[int] = None
    banner: Optional[str] = None
    service: ServiceType = ServiceType.UNKNOWN
    service_version: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    cves: List[Dict[str, Any]] = []
    is_new: bool = True


class ScanConfig(BaseModel):
    targets: List[str] = []
    asns: List[int] = []
    ports: str = "1-1024"
    rate: int = 1000
    banners: bool = True
    retries: int = 2
    wait: int = 30
    adapter_ip: Optional[str] = None
    adapter_port: Optional[int] = None
    nmap_validation: bool = False
    nmap_top_ports: int = 50


class TelegramConfig(BaseModel):
    enabled: bool = False
    bot_token: Optional[str] = None
    chat_id: Optional[str] = None


class EmailConfig(BaseModel):
    enabled: bool = False
    smtp_host: Optional[str] = None
    smtp_port: int = 587
    user: Optional[str] = None
    password: Optional[str] = None
    to: Optional[str] = None
    use_tls: bool = True


class NotificationConfig(BaseModel):
    telegram: TelegramConfig = TelegramConfig()
    email: EmailConfig = EmailConfig()


class CVEConfig(BaseModel):
    enabled: bool = False
    vulners_api_key: Optional[str] = None


class ExploitDBConfig(BaseModel):
    enabled: bool = True


class SchedulerConfig(BaseModel):
    enabled: bool = False
    interval_minutes: int = 60


class DashboardConfig(BaseModel):
    enabled: bool = False
    host: str = "0.0.0.0"
    port: int = 8080


class DatabaseConfig(BaseModel):
    path: str = "data/findings.db"


class AppConfig(BaseModel):
    scan: ScanConfig
    notifications: NotificationConfig
    cve: CVEConfig
    exploit_db: ExploitDBConfig = ExploitDBConfig()
    scheduler: SchedulerConfig
    dashboard: DashboardConfig
    database: DatabaseConfig
