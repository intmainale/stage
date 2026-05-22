"""
Adapter: AbuseIPDBEnricherAdapter
Queries the AbuseIPDB v2 API for IP abuse reports and attaches results
to EnrichableEvent.enrichments["abuseipdb"].
"""

import json
import time
import urllib.error
import urllib.parse
import urllib.request

from src.ports.outbound.log_enricher_port import LogEnricher
from src.domain.models.event import EnrichableEvent
from src.domain.exceptions.domain_exceptions import EnrichmentError
from config.settings import Settings

_BASE = "https://api.abuseipdb.com/api/v2/check"
_CACHE: dict[str, dict] = {}
_CACHE_TTL = 300
_STALE_CACHE_TTL = 3600


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

        now = time.time()
        cached = _CACHE.get(entry.ip)
        if cached and (now - cached["_ts"]) < _CACHE_TTL:
            self.apply_enrichment(entry, cached["data"])
            return entry

        params = urllib.parse.urlencode({"ipAddress": entry.ip, "maxAgeInDays": "90"})
        url = f"{_BASE}?{params}"
        req = urllib.request.Request(
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
                _CACHE[entry.ip] = {"data": result, "_ts": now}
                self.apply_enrichment(entry, result)
                self._L.debug("AbuseIPDBEnricherAdapter: enriched %s", entry.ip)

        except urllib.error.HTTPError as http_exc:
            if http_exc.code == 429:  # Too Many Requests
                self._L.warning("AbuseIPDBEnricherAdapter: quota exceeded for %s", entry.ip)
                if self.use_stale_cache(entry, cached, now):
                    return entry
                raise EnrichmentError(
                    f"AbuseIPDBEnricherAdapter: quota exceeded and no valid cache for {entry.ip}"
                ) from http_exc

            if self.use_stale_cache(entry, cached, now):
                return entry
            raise EnrichmentError(
                f"AbuseIPDBEnricherAdapter: HTTP error {http_exc.code} for {entry.ip}: {http_exc.reason}"
            ) from http_exc

        except Exception as exc:  # noqa: BLE001
            if self.use_stale_cache(entry, cached, now):
                return entry
            raise EnrichmentError(f"AbuseIPDBEnricherAdapter: API error for {entry.ip}: {exc}") from exc

        return entry


    def use_stale_cache(self, entry: EnrichableEvent, cached: dict | None, now: float) -> bool:
        if cached and (now - cached["_ts"]) < _STALE_CACHE_TTL:
            self._L.warning("AbuseIPDBEnricherAdapter: using stale cache for %s", entry.ip)
            self.apply_enrichment(entry, cached["data"])
            return True
        return False


    def apply_enrichment(self, entry: EnrichableEvent, data: dict) -> None:
        for key, value in data.items():
            setattr(entry.enrichments.abuseipdb, key, value)
