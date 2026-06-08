import httpx
from typing import List


class ASNResolver:
    BASE_URL = "https://api.bgpview.io"

    @staticmethod
    async def resolve_asn(asn: int) -> List[str]:
        """Resolve ASN to list of IPv4 prefixes using BGPView API."""
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{ASNResolver.BASE_URL}/asn/AS{asn}/prefixes",
                headers={"User-Agent": "masscan-monitor/1.0"},
                timeout=30.0
            )
            response.raise_for_status()
            data = response.json()
            if data.get("status") != "ok":
                return []
            prefixes = data.get("data", {}).get("ipv4_prefixes", [])
            return [p["prefix"] for p in prefixes]

    @staticmethod
    async def resolve_asns(asns: List[int]) -> List[str]:
        """Resolve multiple ASNs to combined list of prefixes."""
        ranges = []
        for asn in asns:
            prefixes = await ASNResolver.resolve_asn(asn)
            ranges.extend(prefixes)
        return ranges
