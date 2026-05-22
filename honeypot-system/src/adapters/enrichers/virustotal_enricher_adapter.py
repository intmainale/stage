"""
Adapter: VirusTotalEnricherAdapter
Queries the VirusTotal v3 API for IP reputation data and attaches the result
to EnrichableEvent.enrichments["virustotal"].
"""

import time
import urllib.request
import json

from src.ports.outbound.log_enricher_port import LogEnricher
from src.domain.models.event import EnrichableEvent
from src.domain.exceptions.domain_exceptions import EnrichmentError
from config.settings import Settings

_VT_BASE = "https://www.virustotal.com/api/v3/ip_addresses"
_CACHE: dict[str, dict] = {}   # simple in-process TTL cache
_CACHE_TTL = 300               # seconds
_STALE_CACHE_TTL = 3600        # allow using stale cache for 1 hour if API quota is exceeded


class VirusTotalEnricherAdapter(LogEnricher):
    """
    Enriches log entries that contain an IP address with VirusTotal reputation.
    Set API key via settings key: enrichers.virustotal.api_key
    """

    def __init__(self) -> None:
        super().__init__()
        cfg = Settings.get_instance()
        self._api_key: str = cfg.get("enrichers.virustotal.api_key", "")
        if not self._api_key:
            self._L.warning("VirusTotalEnricherAdapter: no API key configured — will skip enrichment")

    def enrich(self, entry: EnrichableEvent) -> EnrichableEvent:
        if not self._api_key or not entry.ip:
            return entry

        now = time.time()
        cached = _CACHE.get(entry.ip)
        if cached and (now - cached["_ts"]) < _CACHE_TTL:
            self.apply_enrichment(entry, cached["data"])
            return entry

        url = f"{_VT_BASE}/{entry.ip}"
        req = urllib.request.Request(
            url,
            headers={"x-apikey": self._api_key, "Accept": "application/json"},
        )

        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                body = json.loads(resp.read())
                stats = (
                    body.get("data", {})
                        .get("attributes", {})
                        .get("last_analysis_stats", {})
                )
                result = {
                    "malicious":  stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless":   stats.get("harmless", 0),
                    "reputation": stats.get("reputation", 0),
                }
                _CACHE[entry.ip] = {"data": result, "_ts": now}
                
                self.apply_enrichment(entry, result)
                self._L.debug("VirusTotalEnricherAdapter: enriched %s", entry.ip)

        except urllib.error.HTTPError as http_exc:
            if http_exc.code == 429:  # Too Many Requests
                self._L.warning("VirusTotalEnricherAdapter: quota exceeded for %s", entry.ip)
            
                if self.use_stale_cache(entry, cached, now):
                    return entry
                
                raise EnrichmentError(f"VirusTotalEnricherAdapter: quota exceeded and no valid cache for {entry.ip}") from http_exc
            
            if self.use_stale_cache(entry, cached, now):
                return entry
            
            raise EnrichmentError(f"VirusTotalEnricherAdapter: HTTP error {http_exc.code} for {entry.ip}: {http_exc.reason}") from http_exc

        except Exception as exc:  # noqa: BLE001
            raise EnrichmentError(f"VirusTotalEnricherAdapter: enrichment error for {entry.ip}: {exc}") from exc

        return entry
    
    def use_stale_cache(self, entry: EnrichableEvent, cached: dict | None, now: float) -> bool:
        if cached and (now - cached["_ts"]) < _STALE_CACHE_TTL:
            self._L.warning("VirusTotalEnricherAdapter: using stale cache for %s", entry.ip)
            self.apply_enrichment(entry, cached["data"])
            return True
        return False

    def apply_enrichment(self, entry: EnrichableEvent, data: dict) -> None:
        for key, value in data.items():
            setattr(entry.enrichments.virustotal, key, value)