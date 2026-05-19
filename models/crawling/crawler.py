"""
ReconX Model 3 — Crawling Engine
Integrates Katana (primary) and hakrawler (optional fallback).
Falls back to a lightweight requests-based crawler when neither tool is present.

Purely additive — does not touch any existing Model 3 code.
"""

import json
import logging
import os
import shutil
import subprocess
import tempfile
from html.parser import HTMLParser
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse

import requests

logger = logging.getLogger(__name__)

KATANA_BIN = os.path.expanduser(r"~\go\bin\katana.exe")
HAKRAWLER_BIN = "hakrawler"
FFUF_BIN = os.path.expanduser(r"~\go\bin\ffuf.exe")

# Common wordlist locations (first match is used)
_FFUF_WORDLISTS = [
    r"C:\Tools\SecLists\Discovery\Web-Content\raft-small-directories.txt",
    r"C:\Tools\wordlists\dirb\common.txt",
    "/usr/share/seclists/Discovery/Web-Content/raft-small-directories.txt",
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/wordlists/dirb/big.txt",
]

# Maximum endpoints collected per target (keeps scan manageable)
MAX_URLS = 300


# ---------------------------------------------------------------------------
# Minimal HTML link extractor (fallback only — no external deps)
# ---------------------------------------------------------------------------
class _LinkParser(HTMLParser):
    def __init__(self, base_url: str):
        super().__init__()
        self.base_url = base_url
        self.links: List[str] = []
        self.forms: List[str] = []
        self.js_files: List[str] = []

    def handle_starttag(self, tag: str, attrs):
        attr_dict = dict(attrs)
        if tag == "a" and attr_dict.get("href"):
            self.links.append(urljoin(self.base_url, attr_dict["href"]))
        elif tag == "form" and attr_dict.get("action"):
            self.forms.append(urljoin(self.base_url, attr_dict["action"]))
        elif tag == "script" and attr_dict.get("src"):
            src = attr_dict["src"]
            if src.endswith(".js"):
                self.js_files.append(urljoin(self.base_url, src))


class CrawlingEngine:
    """
    Web crawler with three tiers:
      1. Katana  — deep JS-aware crawl (preferred)
      2. hakrawler — lightweight Go crawler (fallback)
      3. Built-in requests crawler — pure-Python last resort
    """

    def __init__(self):
        self._katana = (
            KATANA_BIN if os.path.exists(KATANA_BIN) else shutil.which("katana")
        )
        self._hakrawler = shutil.which(HAKRAWLER_BIN)
        self._ffuf = FFUF_BIN if os.path.exists(FFUF_BIN) else shutil.which("ffuf")
        self._ffuf_wordlist = next(
            (wl for wl in _FFUF_WORDLISTS if os.path.exists(wl)), None
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def crawl(self, url: str, depth: int = 3, timeout: int = 60) -> Dict[str, Any]:
        """
        Crawl *url* and return a discovery dict:
        {
            "urls": [...],
            "forms": [...],
            "js_files": [...],
            "api_routes": [...],
            "parameterized_urls": [...],
            "source": "katana" | "hakrawler" | "builtin" | "none"
        }
        """
        empty = self._empty_result()

        if self._katana:
            result = self._run_katana(url, depth, timeout)
            if result:
                result["source"] = "katana"
                # Augment with ffuf directory brute-force
                ffuf_urls = self._run_ffuf(url, int(timeout * 0.5))
                result["urls"] = _dedup(result["urls"] + ffuf_urls)
                return result

        if self._hakrawler:
            result = self._run_hakrawler(url, depth, timeout)
            if result:
                result["source"] = "hakrawler"
                ffuf_urls = self._run_ffuf(url, int(timeout * 0.5))
                result["urls"] = _dedup(result["urls"] + ffuf_urls)
                return result

        # Pure-Python fallback — limited to depth 1 but always available
        result = self._builtin_crawl(url, timeout)
        ffuf_urls = self._run_ffuf(url, int(timeout * 0.5))
        result["urls"] = _dedup(result["urls"] + ffuf_urls)
        result["source"] = "builtin+ffuf" if ffuf_urls else "builtin"
        return result

    # ------------------------------------------------------------------
    # Katana integration
    # ------------------------------------------------------------------

    def _run_katana(self, url: str, depth: int, timeout: int) -> Optional[Dict]:
        try:
            cmd = [
                self._katana, "-u", url,
                "-d", str(depth),
                "-jc",                          # JS crawling
                "-jsline",                      # Inline JS analysis
                "-rl", "20",                    # Rate limit req/s
                "-timeout", "10",               # Per-request timeout
                "-silent",
                "-jsonl",
                "-ef", "png,jpg,jpeg,gif,css,svg,ico,woff,woff2,ttf,eot",
            ]
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout
            )
            return self._parse_katana_output(proc.stdout)
        except subprocess.TimeoutExpired:
            logger.warning(f"[Crawler] Katana timed out for {url}")
        except Exception as exc:
            logger.debug(f"[Crawler] Katana error for {url}: {exc}")
        return None

    def _parse_katana_output(self, raw: str) -> Dict:
        urls, forms, js_files, api_routes, parameterized = [], [], [], [], []

        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue

            # Try JSONL first
            try:
                entry = json.loads(line)
                # Katana JSONL schema varies by version — handle both
                discovered = (
                    entry.get("request", {}).get("endpoint")
                    or entry.get("endpoint")
                    or entry.get("url")
                    or ""
                )
            except json.JSONDecodeError:
                discovered = line if line.startswith("http") else ""

            if not discovered:
                continue

            urls.append(discovered)
            lower = discovered.lower()

            if lower.endswith(".js"):
                js_files.append(discovered)
            elif any(k in lower for k in ("/api/", "/v1/", "/v2/", "/v3/", "/graphql", "/rest/")):
                api_routes.append(discovered)
            elif "?" in discovered:
                parameterized.append(discovered)

        return {
            "urls": _dedup(urls)[:MAX_URLS],
            "forms": _dedup(forms),
            "js_files": _dedup(js_files),
            "api_routes": _dedup(api_routes),
            "parameterized_urls": _dedup(parameterized),
        }

    # ------------------------------------------------------------------
    # hakrawler integration
    # ------------------------------------------------------------------

    def _run_hakrawler(self, url: str, depth: int, timeout: int) -> Optional[Dict]:
        try:
            cmd = [self._hakrawler, "-d", str(depth), "-s", "-u"]
            proc = subprocess.run(
                cmd, input=url, capture_output=True, text=True, timeout=timeout
            )
            urls, js_files, parameterized = [], [], []
            for line in proc.stdout.splitlines():
                line = line.strip()
                if not line.startswith("http"):
                    continue
                urls.append(line)
                if line.endswith(".js"):
                    js_files.append(line)
                if "?" in line:
                    parameterized.append(line)
            return {
                "urls": _dedup(urls)[:MAX_URLS],
                "forms": [],
                "js_files": _dedup(js_files),
                "api_routes": [],
                "parameterized_urls": _dedup(parameterized),
            }
        except Exception as exc:
            logger.debug(f"[Crawler] hakrawler error: {exc}")
        return None

    # ------------------------------------------------------------------
    # Built-in fallback (depth-1, requests + HTML parser)
    # ------------------------------------------------------------------

    def _builtin_crawl(self, url: str, timeout: int) -> Dict:
        urls, forms, js_files, api_routes, parameterized = [], [], [], [], []
        visited = set()
        queue = [url]
        session = requests.Session()
        session.headers["User-Agent"] = "ReconX-Crawler/1.0"

        # depth-1: only follow links found on the seed page
        while queue and len(urls) < MAX_URLS:
            current = queue.pop(0)
            if current in visited:
                continue
            visited.add(current)

            try:
                resp = session.get(current, timeout=10, allow_redirects=True, verify=False)
                if "text/html" not in resp.headers.get("Content-Type", ""):
                    continue

                parser = _LinkParser(current)
                parser.feed(resp.text)

                for link in parser.links:
                    if _same_origin(link, url) and link not in visited:
                        urls.append(link)
                        queue.append(link)
                        if "?" in link:
                            parameterized.append(link)

                forms.extend(parser.forms)
                js_files.extend(parser.js_files)

            except Exception as exc:
                logger.debug(f"[Crawler] Built-in error on {current}: {exc}")

        # Simple API heuristic
        for u in urls:
            if any(k in u.lower() for k in ("/api/", "/v1/", "/v2/", "/graphql")):
                api_routes.append(u)

        return {
            "urls": _dedup(urls)[:MAX_URLS],
            "forms": _dedup(forms),
            "js_files": _dedup(js_files),
            "api_routes": _dedup(api_routes),
            "parameterized_urls": _dedup(parameterized),
        }

    def _run_ffuf(self, url: str, timeout: int) -> List[str]:
        """
        Run ffuf directory brute-force and return list of discovered URLs.
        Skipped gracefully when ffuf binary or wordlist is missing.
        """
        if not self._ffuf or not self._ffuf_wordlist:
            return []
        try:
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".json", delete=False
            ) as fh:
                output_file = fh.name

            cmd = [
                self._ffuf,
                "-w", self._ffuf_wordlist,
                "-u", f"{url.rstrip('/')}/FUZZ",
                "-mc", "200,201,204,301,302,307,401,403",
                "-o", output_file,
                "-of", "json",
                "-silent",
                "-t", "40",      # 40 concurrent threads
                "-timeout", "5", # per-request timeout
            ]
            subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)

            urls: List[str] = []
            if os.path.exists(output_file):
                with open(output_file, "r") as fh:
                    data = json.load(fh)
                for entry in data.get("results", []):
                    found_url = entry.get("url", "")
                    if found_url:
                        urls.append(found_url)
                os.unlink(output_file)

            if urls:
                logger.info(f"[Crawler/ffuf] {len(urls)} paths found on {url}")
            return urls

        except subprocess.TimeoutExpired:
            logger.warning(f"[Crawler/ffuf] Timed out on {url}")
        except Exception as exc:
            logger.debug(f"[Crawler/ffuf] Error on {url}: {exc}")
        return []

    @staticmethod
    def _empty_result() -> Dict:
        return {
            "urls": [], "forms": [], "js_files": [],
            "api_routes": [], "parameterized_urls": [], "source": "none",
        }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _dedup(lst: List[str]) -> List[str]:
    seen = set()
    result = []
    for item in lst:
        if item and item not in seen:
            seen.add(item)
            result.append(item)
    return result


def _same_origin(link: str, base: str) -> bool:
    try:
        return urlparse(link).netloc == urlparse(base).netloc
    except Exception:
        return False
