"""
ReconX Model 3 — JavaScript Endpoint Analyzer
Fetches JS files and HTML pages, extracts hidden API endpoints, routes,
GraphQL references, Swagger/OpenAPI paths, and AJAX call targets.

Uses pure-Python regex — no LinkFinder binary dependency.
Purely additive — does not touch any existing Model 3 code.
"""

import re
import logging
from typing import Any, Dict, List, Set
from urllib.parse import urlparse, urljoin

import requests

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Regex patterns for JS endpoint extraction
# ---------------------------------------------------------------------------

_ENDPOINT_PATTERNS = [
    # fetch() / axios / jQuery AJAX
    r"""fetch\s*\(\s*['"`]([^'"`\s]+)['"`]""",
    r"""axios\.\w+\s*\(\s*['"`]([^'"`\s]+)['"`]""",
    r"""\$\.(?:ajax|get|post|put|delete)\s*\(\s*['"`]([^'"`\s]+)['"`]""",
    # XMLHttpRequest.open
    r"""\.open\s*\(\s*['"`](?:GET|POST|PUT|DELETE|PATCH)['"`]\s*,\s*['"`]([^'"`\s]+)['"`]""",
    # React Router / Vue Router / Angular paths
    r"""(?:path|to|component|route)\s*:\s*['"`]([/][^'"`\s]+)['"`]""",
    # Generic URL path assignment (href, url, endpoint, route, action, src)
    r"""(?:href|url|endpoint|route|action|src)\s*[=:]\s*['"`]([/][^'"`\s<>{}]+)['"`]""",
    # API path strings starting with /api, /v1, /v2, /admin, /auth, etc.
    r"""['"`](/(?:api|v\d+|admin|auth|user|login|logout|upload|download|search|graphql|swagger|openapi|rest)[^'"`\s<>{}]*)['"`]""",
]

_GRAPHQL_PATTERNS = [
    r"""/graphql""",
    r"""graphqlUri\s*[=:]\s*['"`]([^'"`]+)['"`]""",
    r"""gql`""",
    r"""createHttpLink.*uri.*['"`]([^'"`]+)['"`]""",
]

_SWAGGER_PATTERNS = [
    r"""/swagger(?:\.json|\.yaml|-ui(?:\.html)?)""",
    r"""/api-docs(?:\.json)?""",
    r"""/openapi\.(?:json|yaml)""",
    r"""swaggerUrl\s*[=:]\s*['"`]([^'"`]+)['"`]""",
]

# Paths to ignore (noise reduction)
_NOISE = frozenset([
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".css", ".woff", ".woff2", ".ttf", ".eot", ".map",
    "data:", "javascript:", "mailto:", "#",
])


class JSAnalyzer:
    """
    Fetches and regex-scans JavaScript files and inline HTML scripts to
    surface hidden API routes, GraphQL endpoints, and Swagger references.
    """

    def __init__(self):
        self._session = requests.Session()
        self._session.headers["User-Agent"] = "ReconX-JSAnalyzer/1.0"
        self._session.verify = False

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze_js_files(
        self, js_urls: List[str], base_url: str = ""
    ) -> Dict[str, Any]:
        """
        Analyze up to 20 JS files and aggregate all discovered endpoints.
        Returns:
          { "endpoints": [...], "graphql": [...], "swagger": [...], "total": int }
        """
        endpoints: Set[str] = set()
        graphql: Set[str] = set()
        swagger: Set[str] = set()

        for js_url in js_urls[:20]:
            try:
                result = self._analyze_url(js_url, base_url)
                endpoints.update(result["endpoints"])
                graphql.update(result["graphql"])
                swagger.update(result["swagger"])
            except Exception as exc:
                logger.debug(f"[JSAnalyzer] Skipped {js_url}: {exc}")

        return {
            "endpoints": sorted(endpoints),
            "graphql": sorted(graphql),
            "swagger": sorted(swagger),
            "total": len(endpoints) + len(graphql),
        }

    def analyze_html_page(self, url: str) -> Dict[str, Any]:
        """
        Fetch an HTML page and extract endpoints from inline <script> blocks
        and <form> action attributes.
        Returns: { "endpoints": [...], "forms": [...] }
        """
        endpoints: Set[str] = set()
        forms: Set[str] = set()

        try:
            resp = self._session.get(url, timeout=10, allow_redirects=True)
            html = resp.text

            # Inline scripts
            for block in re.findall(
                r"<script[^>]*>(.*?)</script>", html, re.DOTALL | re.IGNORECASE
            ):
                for path in self._extract_from_text(block, url):
                    endpoints.add(path)

            # Form actions
            for action in re.findall(
                r'<form[^>]+action=["\']([^"\']+)["\']', html, re.IGNORECASE
            ):
                forms.add(urljoin(url, action))

        except Exception as exc:
            logger.debug(f"[JSAnalyzer] HTML page error for {url}: {exc}")

        return {"endpoints": sorted(endpoints), "forms": sorted(forms)}

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _analyze_url(self, js_url: str, base_url: str) -> Dict[str, Any]:
        try:
            resp = self._session.get(js_url, timeout=10)
            if resp.status_code != 200:
                return {"endpoints": [], "graphql": [], "swagger": []}
            return self._analyze_content(resp.text, base_url or js_url)
        except Exception as exc:
            logger.debug(f"[JSAnalyzer] Fetch error {js_url}: {exc}")
            return {"endpoints": [], "graphql": [], "swagger": []}

    def _analyze_content(self, content: str, base_url: str) -> Dict[str, Any]:
        endpoints: Set[str] = set()
        graphql: Set[str] = set()
        swagger: Set[str] = set()
        origin = _origin(base_url)

        for path in self._extract_from_text(content, base_url):
            endpoints.add(path)

        # GraphQL detection
        for pattern in _GRAPHQL_PATTERNS:
            for m in re.finditer(pattern, content, re.IGNORECASE):
                try:
                    gql_path = m.group(1)
                    graphql.add(urljoin(base_url, gql_path) if gql_path.startswith("/") else gql_path)
                except IndexError:
                    graphql.add(f"{origin}/graphql")

        # Swagger / OpenAPI detection
        for pattern in _SWAGGER_PATTERNS:
            for m in re.finditer(pattern, content, re.IGNORECASE):
                try:
                    sw_path = m.group(1) if m.lastindex else m.group(0)
                    swagger.add(urljoin(base_url, sw_path))
                except Exception:
                    swagger.add(f"{origin}/swagger.json")

        return {
            "endpoints": sorted(endpoints),
            "graphql": sorted(graphql),
            "swagger": sorted(swagger),
        }

    def _extract_from_text(self, text: str, base_url: str) -> List[str]:
        """Apply all endpoint patterns to raw text and return resolved URLs."""
        found: Set[str] = set()
        for pattern in _ENDPOINT_PATTERNS:
            for m in re.finditer(pattern, text, re.IGNORECASE):
                raw = m.group(1).strip()
                if not self._is_valid(raw):
                    continue
                resolved = urljoin(base_url, raw) if raw.startswith("/") else raw
                if resolved.startswith("http"):
                    found.add(resolved)
                elif raw.startswith("/"):
                    found.add(f"{_origin(base_url)}{raw}")
        return list(found)

    @staticmethod
    def _is_valid(path: str) -> bool:
        if not path or len(path) < 2 or len(path) > 300:
            return False
        if any(path.lower().endswith(n) or path.startswith(n) for n in _NOISE):
            return False
        # Skip template variables like ${...} or {{...}}
        if re.search(r"[{$]", path):
            return False
        return True


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _origin(url: str) -> str:
    """Return scheme://host from a URL."""
    try:
        p = urlparse(url)
        return f"{p.scheme}://{p.netloc}"
    except Exception:
        return ""
