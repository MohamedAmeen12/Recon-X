"""
ReconX Model 3 — Crawling & Endpoint Discovery Extension
Purely additive layer — does not modify any existing Model 3 logic.
"""
from models.crawling.pipeline import CrawlingPipeline

__all__ = ["CrawlingPipeline"]
