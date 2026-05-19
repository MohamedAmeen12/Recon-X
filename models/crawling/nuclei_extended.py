"""
ReconX Model 3 — Extended Nuclei Scanner
Runs Nuclei against ALL crawled endpoints (not just CVE-specific targets).

IMPORTANT: This does NOT replace active_validator.py / run_nuclei_validation().
The existing per-CVE Nuclei validation is preserved and runs independently.
This module adds broad surface-level scanning across discovered endpoints.

Purely additive — does not touch any existing Model 3 code.
"""

import json
import logging
import os
import shutil
import subprocess
import tempfile
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

_NUCLEI_BIN = os.path.expanduser(r"~\go\bin\nuclei.exe")

# Only scan severity levels that matter for recon (skip info to keep it fast)
_SCAN_SEVERITIES = "critical,high,medium"

# Hard cap on endpoints fed to Nuclei per target (prevents runaway scans)
_MAX_ENDPOINTS = 100


class NucleiExtendedScanner:
    """
    Scans a list of crawled endpoints with Nuclei using broad template coverage.
    Complements (does not replace) the existing per-CVE active_validator.py.
    """

    def __init__(self):
        self._bin = _NUCLEI_BIN if os.path.exists(_NUCLEI_BIN) else shutil.which("nuclei")
        self.available = bool(self._bin)

    def scan_endpoints(
        self,
        endpoints: List[Dict[str, Any]],
        target_domain: str,
        timeout: int = 180,
    ) -> List[Dict[str, Any]]:
        """
        Run Nuclei against up to _MAX_ENDPOINTS discovered endpoints.

        Args:
            endpoints: Enriched endpoint dicts from EndpointCollector.
            target_domain: Used only for logging.
            timeout: Subprocess timeout in seconds.

        Returns:
            List of finding dicts, each tagged with the discovery source.
        """
        if not self.available:
            logger.warning("[NucleiExtended] Nuclei binary not found — skipping extended scan.")
            return []

        if not endpoints:
            return []

        # Prioritise high-value endpoints
        urls = [
            ep["url"]
            for ep in sorted(
                endpoints,
                key=lambda e: (-int(e.get("is_high_value", False)), -int(e.get("is_api", False))),
            )
            if ep.get("url", "").startswith("http")
        ][:_MAX_ENDPOINTS]

        if not urls:
            return []

        logger.info(f"[NucleiExtended] Scanning {len(urls)} endpoints on {target_domain}")

        targets_file: Optional[str] = None
        output_file: Optional[str] = None

        try:
            # Write target list to a temp file
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".txt", delete=False, encoding="utf-8"
            ) as fh:
                fh.write("\n".join(urls))
                targets_file = fh.name

            output_file = targets_file.replace(".txt", "_findings.jsonl")

            cmd = [
                self._bin,
                "-l", targets_file,
                "-json-export", output_file,
                "-silent",
                "-rl", "50",
                "-timeout", "10",
                "-retries", "1",
                "-severity", _SCAN_SEVERITIES,
                "-H", "User-Agent: ReconX-Scanner/1.0",
            ]
            subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)

            findings = self._parse_output(output_file, endpoints)
            logger.info(
                f"[NucleiExtended] {len(findings)} findings on {len(urls)} endpoints for {target_domain}"
            )
            return findings

        except subprocess.TimeoutExpired:
            logger.warning(f"[NucleiExtended] Timeout scanning {target_domain}")
        except Exception as exc:
            logger.error(f"[NucleiExtended] Error: {exc}")
        finally:
            for path in filter(None, [targets_file, output_file]):
                try:
                    if os.path.exists(path):
                        os.unlink(path)
                except Exception:
                    pass

        return []

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_output(
        output_file: str, endpoints: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        if not output_file or not os.path.exists(output_file):
            return []

        # Build lookup: url → discovery source
        source_map = {ep["url"]: ep.get("source", "crawler") for ep in endpoints}

        findings: List[Dict[str, Any]] = []
        seen: set = set()

        with open(output_file, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    vuln = json.loads(line)
                except json.JSONDecodeError:
                    continue

                template_id = vuln.get("template-id", "")
                matched_at = vuln.get("matched-at", "")
                dedup_key = f"{template_id}::{matched_at}"

                if dedup_key in seen:
                    continue
                seen.add(dedup_key)

                info = vuln.get("info", {})
                findings.append({
                    "template_id": template_id,
                    "name": info.get("name", ""),
                    "severity": info.get("severity", ""),
                    "matched_at": matched_at,
                    "host": vuln.get("host", ""),
                    "description": info.get("description", ""),
                    "tags": info.get("tags", []),
                    "references": info.get("reference", []),
                    "source": "nuclei_extended",
                    "discovery_source": source_map.get(matched_at, "crawler"),
                })

        return findings
