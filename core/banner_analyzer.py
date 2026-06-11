import re
from typing import Optional, Tuple
from core.models import PortFinding, ServiceType

class BannerAnalyzer:
    SIGNATURES = {
        ServiceType.SSH: [
            re.compile(r'^SSH-2\.0-([^\s\r\n]+)', re.IGNORECASE), # ИСПРАВЛЕНО
            re.compile(r'^SSH-1\.99-', re.IGNORECASE),
        ],
        ServiceType.HTTP: [
            re.compile(r'^HTTP/1\.[01]', re.IGNORECASE),
            re.compile(r'^<\?xml', re.IGNORECASE),
            re.compile(r'^<html', re.IGNORECASE),
            re.compile(r'^<!DOCTYPE', re.IGNORECASE),
            re.compile(r'^\{.*\}$', re.DOTALL),
        ],
        ServiceType.FTP: [
            re.compile(r'^220 .*FTP', re.IGNORECASE),
            re.compile(r'^220-.*FTP', re.IGNORECASE),
            re.compile(r'^220 .*FileZilla', re.IGNORECASE),
        ],
        ServiceType.SMTP: [
            re.compile(r'^220 .*SMTP', re.IGNORECASE),
            re.compile(r'^220 .*ESMTP', re.IGNORECASE),
            re.compile(r'^220 .*Postfix', re.IGNORECASE),
        ],
        ServiceType.TELNET: [
            re.compile(r'^Welcome to', re.IGNORECASE),
            re.compile(r'^login:', re.IGNORECASE),
            re.compile(r'^Password:', re.IGNORECASE),
        ],
        ServiceType.MYSQL: [re.compile(r'mysql', re.IGNORECASE)],
        ServiceType.POSTGRESQL: [re.compile(r'postgresql', re.IGNORECASE)],
        ServiceType.RDP: [re.compile(r'^\x03\x00\x00', re.DOTALL)],
        ServiceType.VNC: [re.compile(r'^RFB ', re.IGNORECASE)],
    }
    
    PORT_MAP = {
        22: ServiceType.SSH, 23: ServiceType.TELNET, 25: ServiceType.SMTP,
        53: ServiceType.UNKNOWN, 80: ServiceType.HTTP, 110: ServiceType.UNKNOWN,
        143: ServiceType.UNKNOWN, 443: ServiceType.HTTPS, 445: ServiceType.UNKNOWN,
        993: ServiceType.UNKNOWN, 995: ServiceType.UNKNOWN, 1723: ServiceType.UNKNOWN,
        3306: ServiceType.MYSQL, 3389: ServiceType.RDP, 5432: ServiceType.POSTGRESQL,
        5900: ServiceType.VNC, 8080: ServiceType.HTTP, 8443: ServiceType.HTTPS,
    }

    @staticmethod
    def analyze(finding: PortFinding) -> PortFinding:
        banner = finding.banner or ""
        service = ServiceType.UNKNOWN
        version = None

        for svc, patterns in BannerAnalyzer.SIGNATURES.items():
            for pattern in patterns:
                match = pattern.search(banner)
                if match:
                    service = svc
                    if match.groups():
                        version = match.group(1)
                    break
            if service != ServiceType.UNKNOWN:
                break

        if service == ServiceType.UNKNOWN:
            service = BannerAnalyzer.PORT_MAP.get(finding.port, ServiceType.UNKNOWN)

        if service in (ServiceType.HTTP, ServiceType.HTTPS) and banner:
            server_match = re.search(r'Server:\s*([^\r\n]+)', banner, re.IGNORECASE) # ИСПРАВЛЕНО
            if server_match:
                version = server_match.group(1).strip()

        if service == ServiceType.SSH and banner:
            ssh_match = re.search(r'^SSH-2\.0-([^\s\r\n]+)', banner, re.IGNORECASE) # ИСПРАВЛЕНО
            if ssh_match:
                version = ssh_match.group(1)

        finding.service = service
        finding.service_version = version
        return finding