import httpx
from typing import List, Dict, Any
from core.models import PortFinding, CVEConfig


class VulnersChecker:
    """Checks CVEs via Vulners API."""

    def __init__(self, config: CVEConfig):
        self.enabled = config.enabled
        self.api_key = config.vulners_api_key
        self.base_url = "https://vulners.com/api/v4"

    async def check(self, finding: PortFinding) -> List[Dict[str, Any]]:
        if not self.enabled or not self.api_key:
            return []

        if not finding.service_version:
            return []

        # Build software audit request
        software = {
            "vendor": finding.service.value,
            "product": finding.service.value,
            "version": finding.service_version
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
