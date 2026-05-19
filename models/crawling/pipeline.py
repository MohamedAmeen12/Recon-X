"""
ReconX Model 3 — Crawling Pipeline Orchestrator
Coordinates: Crawler → JS Analysis → Endpoint Aggregation → Nuclei → AI Validation

Final architecture per target URL:
  Subdomain/URL
       ↓
  CrawlingEngine       (Katana → hakrawler → built-in fallback)
       ↓
  JSAnalyzer           (JS file fetch + inline script regex)
       ↓
  EndpointCollector    (merge, dedup, parameter extraction)
       ↓
  NucleiExtendedScanner (broad endpoint scan)
       ↓
  CrawlingAIValidator  (confidence scoring)
       ↓
  Structured result merged back into Model 3 tech_results

Purely additive — does not touch any existing Model 3 code.
"""

import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError as FutureTimeout
from typing import Any, Dict, List

from models.crawling.crawler import CrawlingEngine
from models.crawling.js_analyzer import JSAnalyzer
from models.crawling.endpoint_collector import EndpointCollector
from models.crawling.nuclei_extended import NucleiExtendedScanner
from models.crawling.ai_validator import CrawlingAIValidator

logger = logging.getLogger(__name__)

# Per-subdomain pipeline hard timeout (seconds)
_PIPELINE_TIMEOUT = 300


class CrawlingPipeline:
    """
    Executes the full crawling pipeline for one or many target URLs.
    Each run is self-contained and can be called in parallel.
    """

    def __init__(self):
        self._crawler = CrawlingEngine()
        self._js = JSAnalyzer()
        self._collector = EndpointCollector()
        self._nuclei = NucleiExtendedScanner()
        self._validator = CrawlingAIValidator()

    # ------------------------------------------------------------------
    # Single-URL pipeline
    # ------------------------------------------------------------------

    def run(
        self,
        url: str,
        target_domain: str,
        depth: int = 3,
        crawl_timeout: int = 60,
        nuclei_timeout: int = 180,
        enable_ai_validation: bool = True,
    ) -> Dict[str, Any]:
        """
        Full pipeline for a single URL.

        Returns:
        {
            "url": str,
            "target_domain": str,
            "crawl_result": { source, urls_discovered, js_files_found, api_routes_found },
            "js_analysis": { js_endpoints_found, graphql_found, swagger_found, total_js_endpoints },
            "endpoint_collection": { endpoints, total, with_params, api_count, ... },
            "nuclei_findings": [...],
            "validated_findings": [...],
            "summary": { total_endpoints, api_endpoints, nuclei_findings, confirmed_findings, ... },
            "elapsed_seconds": float,
            "error": str | None
        }
        """
        t0 = time.time()
        logger.info(f"[CrawlingPipeline] ▶ {url}")

        result: Dict[str, Any] = {
            "url": url,
            "target_domain": target_domain,
            "crawl_result": {},
            "js_analysis": {},
            "endpoint_collection": {"endpoints": [], "total": 0},
            "nuclei_findings": [],
            "validated_findings": [],
            "summary": {},
            "elapsed_seconds": 0.0,
            "error": None,
        }

        try:
            # ── 1. Crawl ────────────────────────────────────────────────
            crawl = self._crawler.crawl(url, depth=depth, timeout=crawl_timeout)
            result["crawl_result"] = {
                "source": crawl.get("source"),
                "urls_discovered": len(crawl.get("urls", [])),
                "js_files_found": len(crawl.get("js_files", [])),
                "api_routes_found": len(crawl.get("api_routes", [])),
            }
            logger.info(
                f"[CrawlingPipeline] Crawl ({crawl.get('source')}) — "
                f"{result['crawl_result']['urls_discovered']} URLs, "
                f"{result['crawl_result']['js_files_found']} JS files"
            )

            # ── 2. JS Analysis ──────────────────────────────────────────
            js_files = crawl.get("js_files", [])
            js_res = self._js.analyze_js_files(js_files, base_url=url) if js_files else {}
            html_res = self._js.analyze_html_page(url)

            all_js_eps = list(set(
                js_res.get("endpoints", [])
                + js_res.get("graphql", [])
                + js_res.get("swagger", [])
                + html_res.get("endpoints", [])
            ))
            result["js_analysis"] = {
                "js_endpoints_found": len(js_res.get("endpoints", [])),
                "graphql_found": len(js_res.get("graphql", [])),
                "swagger_found": len(js_res.get("swagger", [])),
                "inline_endpoints": len(html_res.get("endpoints", [])),
                "total_js_endpoints": len(all_js_eps),
            }
            logger.info(f"[CrawlingPipeline] JS analysis — {len(all_js_eps)} endpoints")

            # ── 3. Aggregate ────────────────────────────────────────────
            collection = self._collector.collect(
                base_url=url,
                crawled_urls=crawl.get("urls", []),
                js_endpoints=all_js_eps,
                form_actions=crawl.get("forms", []) + html_res.get("forms", []),
                api_routes=crawl.get("api_routes", []),
                parameterized_urls=crawl.get("parameterized_urls", []),
            )
            result["endpoint_collection"] = collection
            logger.info(
                f"[CrawlingPipeline] Aggregated {collection['total']} unique endpoints "
                f"({collection['api_count']} API, {collection['high_value_count']} high-value)"
            )

            # ── 4. Extended Nuclei Scan ─────────────────────────────────
            nuclei_findings = self._nuclei.scan_endpoints(
                collection.get("endpoints", []),
                target_domain,
                timeout=nuclei_timeout,
            )
            result["nuclei_findings"] = nuclei_findings
            logger.info(f"[CrawlingPipeline] Nuclei extended — {len(nuclei_findings)} findings")

            # ── 5. AI Validation ────────────────────────────────────────
            if nuclei_findings and enable_ai_validation:
                validated = self._validator.validate_findings(
                    nuclei_findings, collection, target_domain
                )
            else:
                # Tag each finding with default confidence when AI validation skipped
                validated = [
                    {**f, "confidence_level": "LOW",
                     "confidence_explanation": "AI validation skipped.",
                     "is_confirmed": False}
                    for f in nuclei_findings
                ]
            result["validated_findings"] = validated

        except Exception as exc:
            logger.error(f"[CrawlingPipeline] Error for {url}: {exc}")
            result["error"] = str(exc)

        elapsed = round(time.time() - t0, 2)
        result["elapsed_seconds"] = elapsed
        result["summary"] = {
            "total_endpoints": result["endpoint_collection"].get("total", 0),
            "api_endpoints": result["endpoint_collection"].get("api_count", 0),
            "high_value_endpoints": result["endpoint_collection"].get("high_value_count", 0),
            "parameterized_endpoints": result["endpoint_collection"].get("with_params", 0),
            "nuclei_findings": len(result["nuclei_findings"]),
            "confirmed_findings": sum(
                1 for f in result["validated_findings"] if f.get("is_confirmed")
            ),
            "elapsed_seconds": elapsed,
        }

        logger.info(
            f"[CrawlingPipeline] ✓ {url} — "
            f"{result['summary']['total_endpoints']} endpoints | "
            f"{result['summary']['nuclei_findings']} findings | "
            f"{elapsed}s"
        )
        return result

    # ------------------------------------------------------------------
    # Multi-subdomain runner
    # ------------------------------------------------------------------

    def run_for_subdomains(
        self,
        subdomains_data: List[Dict[str, Any]],
        max_workers: int = 3,
        **kwargs,
    ) -> List[Dict[str, Any]]:
        """
        Run the crawling pipeline in parallel across multiple subdomains.

        Args:
            subdomains_data: List of dicts with "url" and/or "subdomain" keys.
            max_workers: Max parallel pipelines.
            **kwargs: Forwarded to self.run().
        """
        results: List[Dict[str, Any]] = []

        if not subdomains_data:
            return results

        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            future_map = {}
            for item in subdomains_data:
                url = item.get("url") or f"http://{item.get('subdomain', '')}"
                domain = item.get("subdomain", "")
                future_map[pool.submit(self.run, url, domain, **kwargs)] = url

            for future in as_completed(future_map):
                url = future_map[future]
                try:
                    results.append(future.result(timeout=_PIPELINE_TIMEOUT))
                except FutureTimeout:
                    logger.warning(f"[CrawlingPipeline] Timed out: {url}")
                    results.append({
                        "url": url, "error": "pipeline_timeout",
                        "summary": {}, "validated_findings": [],
                        "endpoint_collection": {"endpoints": [], "total": 0},
                    })
                except Exception as exc:
                    logger.error(f"[CrawlingPipeline] Failed for {url}: {exc}")
                    results.append({
                        "url": url, "error": str(exc),
                        "summary": {}, "validated_findings": [],
                        "endpoint_collection": {"endpoints": [], "total": 0},
                    })

        return results
