"""
Bug Bounty MCP — Solodit API Adapter
Handles API queries, caching, rate limiting, and response normalization.
"""

import json
import time
import requests
from typing import Optional
from db import Database


class SoloditAdapter:
    BASE_URL = "https://solodit.cyfrin.io/api/v1/solodit"
    
    def __init__(self, api_key: str, db: Database, rate_limit: int = 20,
                 rate_window: int = 60):
        self.api_key = api_key
        self.db = db
        self.rate_limit = rate_limit
        self.rate_window = rate_window
        self._requests_made = []
        self._last_rate_remaining = rate_limit

    def _headers(self):
        return {
            "X-Cyfrin-API-Key": self.api_key,
            "Content-Type": "application/json"
        }

    def _check_rate_limit(self) -> bool:
        """Check if we can make a request. Returns True if allowed."""
        now = time.time()
        # Clean old requests outside the window
        self._requests_made = [t for t in self._requests_made if now - t < self.rate_window]
        if len(self._requests_made) >= self.rate_limit:
            return False
        return True

    def _wait_for_rate_limit(self):
        """Block until a request slot is available."""
        if self._check_rate_limit():
            return
        now = time.time()
        oldest = min(self._requests_made)
        wait = self.rate_window - (now - oldest)
        if wait > 0:
            time.sleep(wait + 0.5)
        self._requests_made = [t for t in self._requests_made if time.time() - t < self.rate_window]

    def _make_request(self, filters: dict, page: int = 1, page_size: int = 20) -> Optional[dict]:
        """Make a raw API request to Solodit. Returns parsed JSON or None."""
        if page_size > 100:
            page_size = 100
        if page_size < 1:
            page_size = 1

        self._wait_for_rate_limit()
        
        payload = {"filters": filters, "page": page, "pageSize": page_size}
        self._requests_made.append(time.time())

        try:
            resp = requests.post(
                f"{self.BASE_URL}/findings",
                headers=self._headers(),
                json=payload,
                timeout=30
            )
        except requests.RequestException as e:
            return {"error": f"Request failed: {str(e)}"}

        if resp.status_code == 429:
            retry_after = int(resp.headers.get("Retry-After", self.rate_window))
            return {"error": "rate_limited", "retry_after": retry_after}

        if resp.status_code != 200:
            return {"error": f"HTTP {resp.status_code}: {resp.text[:200]}"}

        try:
            data = resp.json()
        except Exception:
            return {"error": "Invalid JSON response"}

        # Track rate limit from response
        rl = data.get("rateLimit", {})
        self._last_rate_remaining = rl.get("remaining", self.rate_limit)

        return data

    def search(self, keywords: str = None, impact: list = None,
               protocol: str = None, tags: list = None,
               firms: list = None, languages: list = None,
               protocol_category: list = None,
               min_finders: str = None, max_finders: str = None,
               reported: str = None, quality_score: int = None,
               rarity_score: int = None,
               page: int = 1, page_size: int = 20,
               audit_id: str = None, use_cache: bool = True) -> dict:
        """
        Search Solodit findings. Returns dict with findings + metadata.
        
        If use_cache=True, checks SQLite cache first for identical queries.
        New results are cached in SQLite.
        """
        filters = {}
        if keywords:
            filters["keywords"] = keywords
        if impact:
            filters["impact"] = impact
        if protocol:
            filters["protocol"] = protocol
        if tags:
            filters["tags"] = [{"value": t} for t in tags]
        if firms:
            filters["firms"] = [{"value": f} for f in firms]
        if languages:
            filters["languages"] = [{"value": l} for l in languages]
        if protocol_category:
            filters["protocolCategory"] = [{"value": c} for c in protocol_category]
        if min_finders:
            filters["minFinders"] = min_finders
        if max_finders:
            filters["maxFinders"] = max_finders
        if reported:
            filters["reported"] = {"value": reported}
        if quality_score is not None:
            filters["qualityScore"] = quality_score
        if rarity_score is not None:
            filters["rarityScore"] = rarity_score

        # Make API request
        data = self._make_request(filters, page, page_size)
        
        if "error" in data:
            return data

        findings = data.get("findings", [])
        metadata = data.get("metadata", {})
        rate_limit = data.get("rateLimit", {})

        # Cache findings in SQLite
        finding_ids = []
        for f in findings:
            sid = self.db.upsert_solodit_finding(f)
            finding_ids.append(sid)

        # Log the query
        if audit_id:
            self.db.log_precedent_query(
                audit_id, keywords or "", filters,
                metadata.get("totalResults", 0),
                len(findings), rate_limit.get("remaining", 0),
                page, page_size, finding_ids
            )

        return {
            "findings": findings,
            "total_results": metadata.get("totalResults", 0),
            "page": metadata.get("currentPage", page),
            "page_size": metadata.get("pageSize", page_size),
            "total_pages": metadata.get("totalPages", 1),
            "rate_limit_remaining": rate_limit.get("remaining", 0),
            "rate_limit_reset": rate_limit.get("reset", 0),
            "query_keywords": keywords,
            "cached_ids": finding_ids,
        }

    def get_finding_by_title(self, title_keywords: str, audit_id: str = None) -> Optional[dict]:
        """No get-by-ID endpoint exists. Search by title keywords instead."""
        result = self.search(keywords=title_keywords, page_size=5, audit_id=audit_id)
        if "error" in result:
            return None
        findings = result.get("findings", [])
        if not findings:
            return None
        # Return best match (highest search_rank)
        best = max(findings, key=lambda f: f.get("search_rank", 0))
        return best

    def get_finding_detail(self, solodit_id: str) -> Optional[dict]:
        """Get finding from SQLite cache by ID."""
        return self.db.get_solodit_finding(solodit_id)

    def search_by_pattern(self, pattern_description: str, audit_id: str = None,
                          max_results: int = 20) -> dict:
        """
        Search by vulnerability pattern description.
        Optimized for multi-word phrases that work best with Solodit search.
        """
        return self.search(
            keywords=pattern_description,
            page_size=max_results,
            audit_id=audit_id
        )

    def get_all_pages(self, keywords: str, impact: list = None,
                      max_pages: int = 10, audit_id: str = None) -> list:
        """
        Paginate through all results for a query.
        Respects rate limit. Returns all findings.
        """
        all_findings = []
        page = 1
        while page <= max_pages:
            result = self.search(
                keywords=keywords, impact=impact,
                page=page, page_size=100,
                audit_id=audit_id
            )
            if "error" in result:
                break
            findings = result.get("findings", [])
            if not findings:
                break
            all_findings.extend(findings)
            total_pages = result.get("total_pages", 1)
            if page >= total_pages:
                break
            page += 1
        return all_findings

    def rate_limit_status(self) -> dict:
        """Return current rate limit status."""
        return {
            "remaining": self._last_rate_remaining,
            "limit": self.rate_limit,
            "window_seconds": self.rate_window,
            "requests_in_window": len(self._requests_made),
        }
