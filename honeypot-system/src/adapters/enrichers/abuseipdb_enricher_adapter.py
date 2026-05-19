"""
Adapter: AbuseIPDBEnricherAdapter
Queries the AbuseIPDB v2 API for IP abuse reports and attaches results
to EnrichableEvent.enrichments["abuseipdb"].
"""

import json
import time
import urllib.parse
import urllib.request

from src.ports.outbound.log_enricher_port import LogEnricher
from src.domain.models.event import EnrichableEvent
from src.domain.exceptions.domain_exceptions import EnrichmentError
from config.settings import Settings

_BASE = "https://api.abuseipdb.com/api/v2/check"
_CACHE: dict[str, dict] = {}
_CACHE_TTL = 300


class AbuseIPDBEnricherAdapter(LogEnricher):
    """
    Enriches log entries with AbuseIPDB confidence scores.
    Set API key via settings key: enrichers.abuseipdb.api_key
    """

    def __init__(self) -> None:
        super().__init__()
        cfg = Settings.get_instance()
        self._api_key: str = cfg.get("enrichers.abuseipdb.api_key", "")
        if not self._api_key:
            self._L.warning("AbuseIPDBEnricherAdapter: no API key configured — will skip enrichment")

    def enrich(self, entry: EnrichableEvent) -> EnrichableEvent:
        if not self._api_key or not entry.ip:
            return entry

        cached = _CACHE.get(entry.ip)
        if cached and (time.time() - cached["_ts"]) < _CACHE_TTL:
            #entry.enrich("abuseipdb", cached["data"])
            for key, value in cached["data"].items():
                setattr(entry.enrichments.abuseipdb, key, value)
            return entry

        params = urllib.parse.urlencode({"ipAddress": entry.ip, "maxAgeInDays": "90"})
        url    = f"{_BASE}?{params}"
        req    = urllib.request.Request(
            url,
            headers={"Key": self._api_key, "Accept": "application/json"},
        )

        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                body = json.loads(resp.read())
                data = body.get("data", {})
                result = {
                    "abuse_confidence_score":   data.get("abuseConfidenceScore", 0),
                    "total_reports":            data.get("totalReports", 0),
                    "country":                  data.get("countryName", ""),
                    "isp":                      data.get("isp", ""),
                    "usage_type":               data.get("usageType", ""),
                }
                _CACHE[entry.ip] = {"data": result, "_ts": time.time()}
                #entry.enrich("abuseipdb", result)
                for key, value in result.items():
                    setattr(entry.enrichments.abuseipdb, key, value)

                self._L.debug("AbuseIPDBEnricherAdapter: enriched %s", entry.ip)

        except Exception as exc:  # noqa: BLE001
            raise EnrichmentError(f"AbuseIPDBEnricherAdapter: API error for {entry.ip}: {exc}") from exc

        return entry