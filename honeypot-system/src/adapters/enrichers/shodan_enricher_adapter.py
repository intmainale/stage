"""
Adapter: ShodanEnricherAdapter
Queries the Shodan API for host information and attaches open ports / tags
to EnrichableEvent.enrichments["shodan"].
"""

import json
import time
import urllib.request

from src.ports.outbound.log_enricher_port import LogEnricher
from src.domain.models.event import EnrichableEvent
from src.domain.exceptions.domain_exceptions import EnrichmentError
from config.settings import Settings

_BASE = "https://api.shodan.io/shodan/host"
_CACHE: dict[str, dict] = {}
_CACHE_TTL = 600   # Shodan data is slower-changing; cache for 10 min


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

        cached = _CACHE.get(entry.ip)
        if cached and (time.time() - cached["_ts"]) < _CACHE_TTL:
            #entry.enrich("shodan", cached["data"])
            for key, value in cached["data"].items():
                setattr(entry.enrichments.shodan, key, value)
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
                _CACHE[entry.ip] = {"data": result, "_ts": time.time()}
                #entry.enrich("shodan", result)
                for key, value in result.items():
                    setattr(entry.enrichments.shodan, key, value)
                self._L.debug("ShodanEnricherAdapter: enriched %s", entry.ip)

        except Exception as exc:  # noqa: BLE001
            raise EnrichmentError(f"ShodanEnricherAdapter: API error for {entry.ip}: {exc}") from exc

        return entry