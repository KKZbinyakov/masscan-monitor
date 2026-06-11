import asyncio
import json
import os
import tempfile
import shutil
from typing import List
from datetime import datetime
from core.models import PortFinding, ScanConfig
from core.asn_resolver import ASNResolver

class MasscanScanner:
    def __init__(self, config: ScanConfig):
        self.config = config

    async def _resolve_targets(self) -> List[str]:
        targets = list(self.config.targets)
        if self.config.asns:
            try:
                asn_ranges = await ASNResolver.resolve_asns(self.config.asns)
                targets.extend(asn_ranges)
                print(f"[ASN] Resolved {len(self.config.asns)} ASNs to {len(asn_ranges)} prefixes")
            except Exception as e:
                print(f"[ASN] Failed to resolve ASNs: {e}")
        return targets

    async def run(self) -> List[PortFinding]:
        if not shutil.which("masscan"):
            raise RuntimeError("masscan binary not found in PATH")
        
        targets = await self._resolve_targets()
        if not targets:
            raise ValueError("No targets specified. Set targets or asns in config.")

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            output_file = f.name
            
        # ОПТИМИЗАЦИЯ: Запись целей во временный файл для обхода лимита ARG_MAX
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("\n".join(targets))
            targets_file = f.name

        cmd = [
            "masscan", "-p", self.config.ports, "--rate", str(self.config.rate),
            "--retries", str(self.config.retries), "--wait", str(self.config.wait),
            "-oJ", output_file, "-iL", targets_file # Используем файл с целями
        ]

        if self.config.banners: cmd.append("--banners")
        if self.config.adapter_ip: cmd.extend(["--adapter-ip", self.config.adapter_ip])
        if self.config.adapter_port: cmd.extend(["--adapter-port", str(self.config.adapter_port)])

        print(f"[MASSCAN] Command: masscan ... -iL {targets_file}")

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            if process.returncode != 0:
                stderr_text = stderr.decode().strip()
                raise RuntimeError(f"Masscan failed (exit {process.returncode}): {stderr_text}")

            findings = self._parse_output(output_file)
            return findings
        finally:
            # Очистка временных файлов
            if os.path.exists(output_file): os.unlink(output_file)
            if os.path.exists(targets_file): os.unlink(targets_file)

    def _parse_output(self, output_file: str) -> List[PortFinding]:
        findings = []
        try:
            with open(output_file, "r") as f:
                content = f.read()
            # ИСПРАВЛЕНО: корректная замена переносов строк
            content = content.replace(",\n]", "\n]") 
            data = json.loads(content)
            if isinstance(data, list):
                for item in data:
                    findings.extend(self._parse_item(item))
            return findings
        except (json.JSONDecodeError, ValueError):
            pass

        with open(output_file, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line in ("[", "]"): continue
                if line.endswith(","): line = line[:-1]
                try:
                    data = json.loads(line)
                    findings.extend(self._parse_item(data))
                except json.JSONDecodeError:
                    continue
        return findings

    def _parse_item(self, data: dict) -> List[PortFinding]:
        findings = []
        ip = data.get("ip")
        if not ip: return findings
        for port_data in data.get("ports", []):
            finding = PortFinding(
                ip=ip, port=port_data.get("port"), protocol=port_data.get("proto", "tcp"),
                status=port_data.get("status", "open"), reason=port_data.get("reason"),
                ttl=port_data.get("ttl"), banner=port_data.get("banner"),
                timestamp=datetime.utcnow()
            )
            findings.append(finding)
        return findings