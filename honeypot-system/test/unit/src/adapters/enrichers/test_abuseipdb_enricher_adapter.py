import json
import time
import urllib.error

import pytest

FIXED_TS = time.time()

from src.domain.models.event import EnrichableEvent
from src.adapters.enrichers.abuseipdb_enricher_adapter import AbuseIPDBEnricherAdapter, _CACHE as ABUSE_CACHE


class DummySettings:
    def __init__(self, value: str):
        self._value = value

    def get(self, key: str, default=None):
        if key.endswith("api_key"):
            return self._value
        return default


@pytest.fixture
def entry():
    ABUSE_CACHE.clear()
    return EnrichableEvent(ip="1.2.3.4")


def test_enrich_success(mocker, entry):
    mocker.patch("config.settings.Settings.get_instance", return_value=DummySettings("KEY123"))
    mock_urlopen = mocker.patch("urllib.request.urlopen")

    response_body = {
        "data": {
            "abuseConfidenceScore": 85,
            "totalReports": 12,
            "countryName": "US",
            "isp": "Example ISP",
            "usageType": "Data Center",
        }
    }
    mock_resp = mock_urlopen.return_value.__enter__.return_value
    mock_resp.read.return_value = json.dumps(response_body).encode("utf-8")

    enricher = AbuseIPDBEnricherAdapter()
    result = enricher.enrich(entry)

    assert result.enrichments.abuseipdb.abuse_confidence_score == 85
    assert result.enrichments.abuseipdb.total_reports == 12
    assert result.enrichments.abuseipdb.country == "US"
    assert result.enrichments.abuseipdb.isp == "Example ISP"
    assert result.enrichments.abuseipdb.usage_type == "Data Center"


def test_enrich_http_429_uses_stale_cache(mocker, entry):
    mocker.patch("config.settings.Settings.get_instance", return_value=DummySettings("KEY123"))
    http_exc = urllib.error.HTTPError(url="", code=429, msg="Too Many Requests", hdrs=None, fp=None)
    mocker.patch("urllib.request.urlopen", side_effect=http_exc)
    ABUSE_CACHE[entry.ip] = {"data": {"abuse_confidence_score": 77}, "_ts": FIXED_TS - 3_500}

    enricher = AbuseIPDBEnricherAdapter()
    result = enricher.enrich(entry)

    assert result.enrichments.abuseipdb.abuse_confidence_score == 77


def test_enrich_without_api_key_returns_entry(mocker, entry):
    mocker.patch("config.settings.Settings.get_instance", return_value=DummySettings(""))

    result = AbuseIPDBEnricherAdapter().enrich(entry)

    assert result is entry
    assert result.enrichments.abuseipdb is None