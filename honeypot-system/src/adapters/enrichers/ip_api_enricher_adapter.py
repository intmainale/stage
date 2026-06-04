"""
Adapter: IPApiEnricherAdapter
Queries the ip-api.com JSON API for geolocation and ASN information
and attaches results to EnrichableEvent.enrichments["ip_api"].
"""

import json
import time
import urllib.error
import urllib.request

from src.ports.outbound.log_enricher_port import LogEnricher
from src.domain.models.event import (
    EnrichableEvent,
    EnrichmentBundle,
    IPApiInfo,
)
from src.domain.exceptions.domain_exceptions import EnrichmentError
from config.settings import Settings

_BASE = "http://ip-api.com/json"
_CACHE: dict[str, dict] = {}
_CACHE_TTL = 300
_STALE_CACHE_TTL = 3600


class IPApiEnricherAdapter(LogEnricher):
    """
    Enriches log entries with geolocation and ASN data from ip-api.com.

    Enable pro features via:
        enrichers.ip_api.api_key
    """

    def __init__(self) -> None:
        super().__init__()

        cfg = Settings.get_instance()
        self._enabled = cfg.get("enrichers.ip_api.api_key", "")

        if not self._enabled:
            self._L.warning("IPApiEnricherAdapter: no API key configured — will continue to enrich with free API")

    def enrich(self, entry: EnrichableEvent) -> EnrichableEvent:
        if not self._enabled or not entry.ip:
            return entry

        if not entry.enrichments:
            entry.enrichments = EnrichmentBundle()

        entry.enrichments.ip_api = IPApiInfo()

        now = time.time()
        cached = _CACHE.get(entry.ip)

        if cached and (now - cached["_ts"]) < _CACHE_TTL:
            self.apply_enrichment(entry, cached["data"])
            return entry

        url = (
            f"{_BASE}/{entry.ip}"
            "?fields=status,message,country,regionName,city,"
            "lat,lon,isp,org,as"
        )

        try:
            with urllib.request.urlopen(url, timeout=5) as resp:
                body = json.loads(resp.read())

                if body.get("status") != "success":
                    raise EnrichmentError(
                        f"IPApiEnricherAdapter: lookup failed for "
                        f"{entry.ip}: {body.get('message', 'unknown error')}"
                    )

                result = {
                    "country": body.get("country", ""),
                    "region_name": body.get("regionName", ""),
                    "city": body.get("city", ""),
                    "latitude": body.get("lat"),
                    "longitude": body.get("lon"),
                    "isp": body.get("isp", ""),
                    "organization": body.get("org", ""),
                    "asn": body.get("as", ""),
                }

                _CACHE[entry.ip] = {
                    "data": result,
                    "_ts": now,
                }

                self.apply_enrichment(entry, result)

                self._L.debug(
                    "IPApiEnricherAdapter: enriched %s",
                    entry.ip,
                )

        except urllib.error.HTTPError as http_exc:
            if self.use_stale_cache(entry, cached, now):
                return entry

            raise EnrichmentError(
                f"IPApiEnricherAdapter: HTTP error "
                f"{http_exc.code} for {entry.ip}: "
                f"{http_exc.reason}"
            ) from http_exc

        except Exception as exc:  # noqa: BLE001
            if self.use_stale_cache(entry, cached, now):
                return entry

            raise EnrichmentError(
                f"IPApiEnricherAdapter: API error "
                f"for {entry.ip}: {exc}"
            ) from exc

        return entry

    def use_stale_cache(
        self,
        entry: EnrichableEvent,
        cached: dict | None,
        now: float,
    ) -> bool:
        if cached and (now - cached["_ts"]) < _STALE_CACHE_TTL:
            self._L.warning(
                "IPApiEnricherAdapter: using stale cache for %s",
                entry.ip,
            )

            self.apply_enrichment(entry, cached["data"])
            return True

        return False

    def apply_enrichment(
        self,
        entry: EnrichableEvent,
        data: dict,
    ) -> None:
        for key, value in data.items():
            setattr(entry.enrichments.ip_api, key, value)