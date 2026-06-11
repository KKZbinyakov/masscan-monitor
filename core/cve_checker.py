import httpx
import re
from typing import List, Dict, Any
from core.models import PortFinding, CVEConfig


class VulnersChecker:
    """Checks CVEs via Vulners API with banner-based vendor/product detection."""

    BANNER_MAP = {
        r'OpenSSH': ('openbsd', 'openssh'),
        r'nginx': ('nginx', 'nginx'),
        r'Apache(?:/|\s)': ('apache', 'http_server'),
        r'Microsoft-IIS': ('microsoft', 'iis'),
        r'lighttpd': ('lighttpd', 'lighttpd'),
        r'ProFTPD': ('proftpd', 'proftpd'),
        r'vsftpd': ('vsftpd', 'vsftpd'),
        r'FileZilla': ('filezilla', 'filezilla_server'),
        r'Postfix': ('postfix', 'postfix'),
        r'Exim': ('exim', 'exim'),
        r'MySQL': ('oracle', 'mysql'),
        r'MariaDB': ('mariadb', 'mariadb'),
        r'PostgreSQL': ('postgresql', 'postgresql'),
        r'Microsoft SQL Server': ('microsoft', 'sql_server'),
        r'OpenSSL': ('openssl', 'openssl'),
        r'PHP': ('php', 'php'),
        r'Tomcat': ('apache', 'tomcat'),
        r'Jetty': ('eclipse', 'jetty'),
    }

    def __init__(self, config: CVEConfig):
        self.enabled = config.enabled
        self.api_key = config.vulners_api_key
        self.base_url = "https://vulners.com/api/v4"

    def _detect_vendor_product(self, finding: PortFinding) -> tuple:
        """Extract real vendor/product from banner or service type."""
        banner = finding.banner or ""
        service = finding.service.value

        for pattern, (vendor, product) in self.BANNER_MAP.items():
            if re.search(pattern, banner, re.IGNORECASE):
                return vendor, product

        service_map = {
            'ssh': ('openbsd', 'openssh'),
            'http': ('apache', 'http_server'),
            'https': ('apache', 'http_server'),
            'ftp': ('proftpd', 'proftpd'),
            'smtp': ('postfix', 'postfix'),
            'mysql': ('oracle', 'mysql'),
            'postgresql': ('postgresql', 'postgresql'),
            'telnet': ('linux', 'telnet'),
            'rdp': ('microsoft', 'remote_desktop'),
            'vnc': ('realvnc', 'vnc'),
        }
        return service_map.get(service, (service, service))

    def _clean_version(self, version: str) -> str:
        """Extract clean version number for Vulners."""
        if not version:
            return ""
        match = re.search(r'[0-9]+(?:\.[0-9]+)+', version)
        return match.group(0) if match else version.split()[0]

    async def check(self, finding: PortFinding) -> List[Dict[str, Any]]:
        if not self.enabled or not self.api_key:
            return []

        version = self._clean_version(finding.service_version or "")
        if not version:
            return []

        vendor, product = self._detect_vendor_product(finding)

        software = {
            "vendor": vendor,
            "product": product,
            "version": version
        }

        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"{self.base_url}/audit/software",
                    headers={
                        "X-Api-Key": self.api_key,
                        "Content-Type": "application/json"
                    },
                    json={
                        "software": [software],
                        "match": "partial",
                        "fields": ["title", "short_description", "href", "published", "cvss"]
                    },
                    timeout=30.0
                )
                response.raise_for_status()
                data = response.json()

                cves = []
                for item in data.get("data", {}).get("software", []):
                    for vuln in item.get("vulnerabilities", []):
                        cves.append({
                            "title": vuln.get("title"),
                            "description": vuln.get("short_description"),
                            "href": vuln.get("href"),
                            "published": vuln.get("published"),
                            "cvss": vuln.get("cvss")
                        })
                return cves
        except Exception:
            return []