"""
ReconX Model 3 — AI Validation Layer (Crawled Findings)
Validates Nuclei findings from the extended crawler scan using Gemini.
Assigns confidence scores and explains evidence.

Safe read-only analysis only — no offensive payloads generated.
Purely additive — does not touch any existing Model 3 code.
"""

import json
import logging
import re
from typing import Any, Dict, List, Tuple

logger = logging.getLogger(__name__)

_CONFIDENCE_ORDER = {"HIGH": 3, "MEDIUM": 2, "LOW": 1, "FALSE_POSITIVE": 0}


class CrawlingAIValidator:
    """
    Two-tier validation:
      1. Gemini AI (when API key is available) — contextual analysis.
      2. Rule-based fallback — uses template severity + endpoint metadata.
    """

    def __init__(self):
        self._gemini = None
        self.available = False
        try:
            from utils.gemini_service import gemini_service
            self._gemini = gemini_service
            self.available = bool(self._gemini and self._gemini.primary_model)
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def validate_findings(
        self,
        findings: List[Dict[str, Any]],
        endpoint_collection: Dict[str, Any],
        target: str,
    ) -> List[Dict[str, Any]]:
        """
        Enrich each finding with confidence_level, confidence_explanation,
        and is_confirmed flag.  Returns findings sorted by confidence.
        """
        if not findings:
            return []

        validated = []
        for finding in findings:
            enriched = dict(finding)

            if self.available:
                confidence, explanation = self._gemini_validate(
                    finding, endpoint_collection, target
                )
            else:
                confidence, explanation = self._rule_based(finding)

            enriched["confidence_level"] = confidence
            enriched["confidence_explanation"] = explanation
            enriched["is_confirmed"] = confidence in ("HIGH", "MEDIUM")
            validated.append(enriched)

        # Sort: HIGH → MEDIUM → LOW → FALSE_POSITIVE
        validated.sort(
            key=lambda x: _CONFIDENCE_ORDER.get(x.get("confidence_level", "LOW"), 0),
            reverse=True,
        )
        return validated

    # ------------------------------------------------------------------
    # Gemini validation
    # ------------------------------------------------------------------

    def _gemini_validate(
        self,
        finding: Dict[str, Any],
        endpoint_collection: Dict[str, Any],
        target: str,
    ) -> Tuple[str, str]:
        context = json.dumps(
            {
                "target": target,
                "finding": {
                    "name": finding.get("name"),
                    "template_id": finding.get("template_id"),
                    "severity": finding.get("severity"),
                    "matched_at": finding.get("matched_at"),
                    "description": finding.get("description"),
                    "tags": finding.get("tags", []),
                    "discovery_source": finding.get("discovery_source"),
                },
                "endpoint_context": {
                    "total_scanned": endpoint_collection.get("total", 0),
                    "api_count": endpoint_collection.get("api_count", 0),
                    "matched_is_api": "/api" in str(finding.get("matched_at", "")).lower(),
                    "matched_is_admin": "/admin" in str(finding.get("matched_at", "")).lower(),
                },
            },
            indent=2,
        )

        prompt = (
            "You are a cybersecurity analyst reviewing a Nuclei vulnerability finding.\n\n"
            "Respond ONLY with a JSON object (no markdown, no extra text):\n"
            '{"confidence":"HIGH|MEDIUM|LOW|FALSE_POSITIVE","reasoning":"<2 sentences>"}\n\n'
            "Confidence criteria:\n"
            "- HIGH: Critical/High severity on API or admin endpoint, CVE template with exact match\n"
            "- MEDIUM: High/Medium severity, plausible but needs manual check\n"
            "- LOW: Generic template, low severity, limited context\n"
            "- FALSE_POSITIVE: Info-level only, no supporting evidence\n\n"
            "DO NOT suggest exploitation. Analyse evidence only."
        )

        try:
            response = self._gemini.ask_gemini(prompt, context)
            m = re.search(r"\{[^{}]+\}", response, re.DOTALL)
            if m:
                data = json.loads(m.group(0))
                conf = data.get("confidence", "LOW")
                if conf not in _CONFIDENCE_ORDER:
                    conf = "LOW"
                return conf, data.get("reasoning", "")
        except Exception as exc:
            logger.debug(f"[AIValidator] Gemini call failed: {exc}")

        return self._rule_based(finding)

    # ------------------------------------------------------------------
    # Rule-based fallback
    # ------------------------------------------------------------------

    @staticmethod
    def _rule_based(finding: Dict[str, Any]) -> Tuple[str, str]:
        severity = str(finding.get("severity", "")).lower()
        template_id = str(finding.get("template_id", "")).lower()
        matched_at = str(finding.get("matched_at", "")).lower()

        if severity == "critical" and "cve-" in template_id:
            return "HIGH", "Critical severity CVE template matched against a specific endpoint."

        if severity == "high" and ("/api/" in matched_at or "/admin" in matched_at):
            return "HIGH", "High severity finding on a sensitive API or admin endpoint."

        if severity in ("high", "critical"):
            return "MEDIUM", "High/critical severity — likely valid but manual confirmation recommended."

        if severity == "medium":
            return "MEDIUM", "Medium severity finding with a plausible attack surface."

        if severity in ("low", "info"):
            return "LOW", "Low/info severity — review manually before actioning."

        return "LOW", "Insufficient template metadata to assign higher confidence."
