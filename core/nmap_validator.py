import asyncio
import xml.etree.ElementTree as ET
import tempfile
import os
from typing import Optional
from core.models import PortFinding


class NmapValidator:
    """Optional Nmap validation for detailed service detection."""

    def __init__(self, enabled: bool = False, top_ports: int = 50):
        self.enabled = enabled
        self.top_ports = top_ports

    async def validate(self, finding: PortFinding) -> Optional[str]:
        if not self.enabled:
            return None

        # Only validate interesting/high-value ports
        interesting_ports = {21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5432, 5900, 8080, 8443}
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
