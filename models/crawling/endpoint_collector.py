"""
ReconX Model 3 — Endpoint Aggregator & Parameter Extractor
Merges endpoints from crawler, JS analysis, forms, and API routes.
Deduplicates intelligently and extracts URL parameters for injection point mapping.

Purely additive — does not touch any existing Model 3 code.
"""

import logging
from typing import Any, Dict, List, Set
from urllib.parse import urljoin, urlparse, parse_qs

logger = logging.getLogger(__name__)

# Parameter names that commonly indicate injection-worthy inputs
_HIGH_VALUE_PARAMS = frozenset([
    "id", "user", "username", "uid", "file", "path", "dir", "url", "uri",
    "redirect", "return", "next", "q", "query", "search", "s", "cmd", "exec",
    "command", "action", "page", "view", "template", "theme", "token", "key",
    "pass", "password", "pwd", "email", "debug", "test", "admin", "lang",
    "language", "type", "format", "callback", "jsonp", "ref", "source",
    "dest", "target", "to", "from", "subject", "message", "content",
    "upload", "download", "import", "export",
])

_API_SEGMENTS = ("/api/", "/v1/", "/v2/", "/v3/", "/v4/", "/rest/", "/graphql", "/soap", "/rpc")
_ADMIN_SEGMENTS = ("/admin", "/panel", "/dashboard", "/management", "/manager", "/control", "/console")
_SENSITIVE_PATHS = (
    "/login", "/signin", "/logout", "/register", "/signup",
    "/upload", "/download", "/import", "/export",
    "/exec", "/run", "/eval", "/shell", "/cmd",
    "/search", "/find", "/query",
    "/config", "/settings", "/setup", "/install",
    "/backup", "/debug", "/test",
)


class EndpointCollector:
    """
    Aggregates, deduplicates, and enriches endpoints from all discovery sources.
    Produces a normalized inventory with parameter analysis and risk annotation.
    """

    def collect(
        self,
        base_url: str,
        crawled_urls: List[str] = None,
        js_endpoints: List[str] = None,
        form_actions: List[str] = None,
        api_routes: List[str] = None,
        parameterized_urls: List[str] = None,
    ) -> Dict[str, Any]:
        """
        Merge all endpoint sources into a deduplicated, enriched inventory.

        Returns:
        {
            "endpoints": [{ url, normalized, source, parameters, is_api,
                            is_admin, is_high_value, path, has_params }],
            "total": int,
            "with_params": int,
            "api_count": int,
            "high_value_count": int,
            "parameter_inventory": { param_name: [urls] },
            "sources": { crawler, javascript, form, api }
        }
        """
        raw: List[Dict[str, str]] = []

        for url in (crawled_urls or []):
            raw.append({"url": url, "source": "crawler"})
        for url in (js_endpoints or []):
            raw.append({"url": self._resolve(url, base_url), "source": "javascript"})
        for url in (form_actions or []):
            raw.append({"url": self._resolve(url, base_url), "source": "form"})
        for url in (api_routes or []):
            raw.append({"url": url, "source": "api"})
        for url in (parameterized_urls or []):
            raw.append({"url": url, "source": "crawler"})

        seen_norm: Set[str] = set()
        enriched: List[Dict[str, Any]] = []

        for item in raw:
            url = item["url"]
            if not url or not url.startswith("http"):
                continue

            norm = self._normalize(url)
            if norm in seen_norm:
                continue
            seen_norm.add(norm)

            params = self._extract_params(url)
            is_api = self._is_api(url)
            is_admin = self._is_admin(url)
            is_high = self._is_high_value(url, params, is_api, is_admin)

            enriched.append({
                "url": url,
                "normalized": norm,
                "source": item["source"],
                "parameters": params,
                "has_params": bool(params),
                "is_api": is_api,
                "is_admin": is_admin,
                "is_high_value": is_high,
                "path": urlparse(url).path,
            })

        # Sort: high-value first, then APIs, then parameterized
        enriched.sort(key=lambda e: (
            -int(e["is_high_value"]),
            -int(e["is_api"]),
            -int(e["has_params"]),
        ))

        param_inventory = self._build_param_inventory(enriched)

        return {
            "endpoints": enriched,
            "total": len(enriched),
            "with_params": sum(1 for e in enriched if e["has_params"]),
            "api_count": sum(1 for e in enriched if e["is_api"]),
            "high_value_count": sum(1 for e in enriched if e["is_high_value"]),
            "parameter_inventory": param_inventory,
            "sources": {
                "crawler": sum(1 for e in enriched if e["source"] == "crawler"),
                "javascript": sum(1 for e in enriched if e["source"] == "javascript"),
                "form": sum(1 for e in enriched if e["source"] == "form"),
                "api": sum(1 for e in enriched if e["source"] == "api"),
            },
        }

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    @staticmethod
    def _resolve(url: str, base_url: str) -> str:
        if url.startswith("http"):
            return url
        if base_url:
            return urljoin(base_url, url)
        return url

    @staticmethod
    def _normalize(url: str) -> str:
        """Strip query string for dedup purposes; also normalise case."""
        try:
            p = urlparse(url)
            return f"{p.scheme}://{p.netloc}{p.path}".rstrip("/").lower()
        except Exception:
            return url.lower()

    @staticmethod
    def _extract_params(url: str) -> List[Dict[str, Any]]:
        """Parse query string into structured parameter list."""
        try:
            qs = urlparse(url).query
            if not qs:
                return []
            params = []
            for name, values in parse_qs(qs, keep_blank_values=True).items():
                params.append({
                    "name": name,
                    "value": values[0] if values else "",
                    "is_high_value": name.lower() in _HIGH_VALUE_PARAMS,
                })
            return params
        except Exception:
            return []

    @staticmethod
    def _is_api(url: str) -> bool:
        return any(seg in url.lower() for seg in _API_SEGMENTS)

    @staticmethod
    def _is_admin(url: str) -> bool:
        return any(seg in url.lower() for seg in _ADMIN_SEGMENTS)

    @staticmethod
    def _is_high_value(
        url: str, params: List[Dict], is_api: bool, is_admin: bool
    ) -> bool:
        if is_api or is_admin:
            return True
        if any(p["is_high_value"] for p in params):
            return True
        url_lower = url.lower()
        return any(seg in url_lower for seg in _SENSITIVE_PATHS)

    @staticmethod
    def _build_param_inventory(
        endpoints: List[Dict[str, Any]],
    ) -> Dict[str, List[str]]:
        """Build param_name → [list of URLs that expose it]."""
        inventory: Dict[str, List[str]] = {}
        for ep in endpoints:
            for p in ep.get("parameters", []):
                name = p["name"]
                inventory.setdefault(name, []).append(ep["url"])
        return inventory
