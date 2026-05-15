"""
Adapter: VirusTotalEnricherAdapter
Queries the VirusTotal v3 API for IP reputation data and attaches the result
to the Event's enrichments dict under the key "virustotal".
"""

import time
import urllib.request
import json

from src.ports.outbound.log_enricher_port import LogEnricher
from src.domain.models.event import Event
from src.domain.exceptions.domain_exceptions import EnrichmentError
from config.settings import Settings

_VT_BASE = "https://www.virustotal.com/api/v3/ip_addresses"
_CACHE: dict[str, dict] = {}   # simple in-process TTL cache
_CACHE_TTL = 300               # seconds


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

    def enrich(self, entry: Event) -> Event:
        if not self._api_key or not entry.ip:
            return entry

        cached = _CACHE.get(entry.ip)
        if cached and (time.time() - cached["_ts"]) < _CACHE_TTL:
            #entry.enrich("virustotal", cached["data"])
            for key, value in cached["data"].items():
                setattr(entry.enrichments.virustotal, key, value)
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
                _CACHE[entry.ip] = {"data": result, "_ts": time.time()}
                #entry.enrich("virustotal", result)
                for key, value in result.items():
                    setattr(entry.enrichments.virustotal, key, value)
                self._L.debug("VirusTotalEnricherAdapter: enriched %s → %s", entry.ip, result)

        except Exception as exc:  # noqa: BLE001
            raise EnrichmentError(f"VirusTotalEnricherAdapter: API error for {entry.ip}: {exc}") from exc

        return entry