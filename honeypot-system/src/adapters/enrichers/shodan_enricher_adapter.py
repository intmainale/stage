"""
Adapter: ShodanEnricherAdapter
Queries the Shodan API for host information and attaches open ports / tags
to EnrichableEvent.enrichments["shodan"].
"""

import json
import time
import urllib.error
import urllib.request

from src.ports.outbound.log_enricher_port import LogEnricher
from src.domain.models.event import EnrichableEvent, ShodanInfo, EnrichmentBundle
from src.domain.exceptions.domain_exceptions import EnrichmentError
from config.settings import Settings

_BASE = "https://api.shodan.io/shodan/host"
_CACHE: dict[str, dict] = {}
_CACHE_TTL = 600   # Shodan data is slower-changing; cache for 10 min
_STALE_CACHE_TTL = 3600  # If API is unavailable, use stale cache up to 1h old


class ShodanEnricherAdapter(LogEnricher):
    """
    Enriches log entries with Shodan host data (open ports, tags, org, …).
    Set API key via settings key: enrichers.shodan.api_key
    """

    def __init__(self) -> None:
        super().__init__()
        cfg = Settings.get_instance()
        self._api_key: str = cfg.get("enrichers.shodan.api_key", "")
        if not self._api_key:
            self._L.warning("ShodanEnricherAdapter: no API key configured — will skip enrichment")

    def enrich(self, entry: EnrichableEvent) -> EnrichableEvent:
        if not self._api_key or not entry.ip:
            return entry

        if not entry.enrichments:
            entry.enrichments = EnrichmentBundle()
        
        entry.enrichments.shodan = ShodanInfo()

        now = time.time()
        cached = _CACHE.get(entry.ip)
        if cached and (now - cached["_ts"]) < _CACHE_TTL:
            self.apply_enrichment(entry, cached["data"])
            return entry

        url = f"{_BASE}/{entry.ip}?key={self._api_key}"

        try:
            with urllib.request.urlopen(url, timeout=5) as resp:
                body = json.loads(resp.read())
                result = {
                    "ports":        body.get("ports", []),
                    "tags":         body.get("tags", []),
                    "asn":          body.get("asn", ""),
                    "os":           body.get("os", ""),
                    "latitude":     body.get("latitude", 0),
                    "longitude":    body.get("longitude", 0),
                }
                _CACHE[entry.ip] = {"data": result, "_ts": now}
                self.apply_enrichment(entry, result)
                self._L.debug("ShodanEnricherAdapter: enriched %s", entry.ip)

        except urllib.error.HTTPError as http_exc:
            if http_exc.code == 429:  # Too Many Requests
                self._L.warning("ShodanEnricherAdapter: quota exceeded for %s", entry.ip)
                if self.use_stale_cache(entry, cached, now):
                    return entry
                raise EnrichmentError(
                    f"ShodanEnricherAdapter: quota exceeded and no valid cache for {entry.ip}"
                ) from http_exc

            if self.use_stale_cache(entry, cached, now):
                return entry
            raise EnrichmentError(
                f"ShodanEnricherAdapter: HTTP error {http_exc.code} for {entry.ip}: {http_exc.reason}"
            ) from http_exc

        except Exception as exc:  # noqa: BLE001
            if self.use_stale_cache(entry, cached, now):
                return entry
            raise EnrichmentError(f"ShodanEnricherAdapter: API error for {entry.ip}: {exc}") from exc

        return entry


    def use_stale_cache(self, entry: EnrichableEvent, cached: dict | None, now: float) -> bool:
        if cached and (now - cached["_ts"]) < _STALE_CACHE_TTL:
            self._L.warning("ShodanEnricherAdapter: using stale cache for %s", entry.ip)
            self.apply_enrichment(entry, cached["data"])
            return True
        return False


    def apply_enrichment(self, entry: EnrichableEvent, data: dict) -> None:
        for key, value in data.items():
            setattr(entry.enrichments.shodan, key, value)
