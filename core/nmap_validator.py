import asyncio
import xml.etree.ElementTree as ET
import tempfile
import os
from typing import Optional, List, Dict
from collections import defaultdict
from core.models import PortFinding


class NmapValidator:
    """Optional Nmap validation for detailed service detection.

    Uses batch mode by default: groups ports by IP and runs a single nmap
    process per host, which is orders of magnitude faster than one nmap
    per port.
    """

    def __init__(self, enabled: bool = False, top_ports: int = 50):
        self.enabled = enabled
        self.top_ports = top_ports

    async def validate(self, finding: PortFinding) -> Optional[str]:
        """Legacy single-port validation (kept for compatibility)."""
        if not self.enabled:
            return None

        interesting_ports = {21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
                             993, 995, 1723, 3306, 3389, 5432, 5900, 8080, 8443}
        if finding.port not in interesting_ports:
            return None

        with tempfile.NamedTemporaryFile(mode="w", suffix=".xml", delete=False) as f:
            output_file = f.name

        cmd = [
            "nmap", "-sV", "-p", str(finding.port),
            "-oX", output_file,
            finding.ip
        ]

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await asyncio.wait_for(process.communicate(), timeout=300)
            version = self._parse_version(output_file)
            os.unlink(output_file)
            return version
        except Exception:
            if os.path.exists(output_file):
                os.unlink(output_file)
            return None

    async def validate_batch(self, findings: List[PortFinding]) -> None:
        """Batch validation: group ports by IP and run one nmap per host."""
        if not self.enabled:
            return

        interesting_ports = {21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
                             993, 995, 1723, 3306, 3389, 5432, 5900, 8080, 8443}

        by_ip: Dict[str, List[PortFinding]] = defaultdict(list)
        for f in findings:
            if f.port in interesting_ports:
                by_ip[f.ip].append(f)

        if not by_ip:
            return

        # Process each IP
        for ip, ip_findings in by_ip.items():
            ports = ",".join(str(f.port) for f in ip_findings)
            with tempfile.NamedTemporaryFile(mode="w", suffix=".xml", delete=False) as f:
                output_file = f.name

            cmd = [
                "nmap", "-sV", "-p", ports,
                "-oX", output_file,
                ip
            ]

            try:
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                await asyncio.wait_for(process.communicate(), timeout=300)
                versions = self._parse_batch(output_file)
                os.unlink(output_file)

                for f in ip_findings:
                    key = (f.ip, f.port)
                    if key in versions:
                        f.service_version = versions[key]
            except Exception:
                if os.path.exists(output_file):
                    os.unlink(output_file)

    def _parse_version(self, output_file: str) -> Optional[str]:
        try:
            tree = ET.parse(output_file)
            root = tree.getroot()
            for port in root.findall('.//port'):
                service = port.find('service')
                if service is not None:
                    version = service.get('version')
                    product = service.get('product')
                    if product and version:
                        return f"{product} {version}"
                    return product or version
        except Exception:
            pass
        return None

    def _parse_batch(self, output_file: str) -> Dict[tuple, str]:
        """Parse nmap XML and return {(ip, port): version_string}."""
        results: Dict[tuple, str] = {}
        try:
            tree = ET.parse(output_file)
            root = tree.getroot()
            for host in root.findall('host'):
                ip_elem = host.find('.//address[@addrtype="ipv4"]')
                if ip_elem is None:
                    continue
                ip = ip_elem.get('addr')
                for port in host.findall('.//port'):
                    port_num = int(port.get('portid'))
                    service = port.find('service')
                    if service is not None:
                        version = service.get('version')
                        product = service.get('product')
                        if product and version:
                            results[(ip, port_num)] = f"{product} {version}"
                        elif product or version:
                            results[(ip, port_num)] = product or version
        except Exception:
            pass
        return results