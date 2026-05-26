import json
import time
import urllib.error

import pytest

FIXED_TS = time.time()

from src.domain.models.event import EnrichableEvent
from src.adapters.enrichers.shodan_enricher_adapter import ShodanEnricherAdapter, _CACHE as SHODAN_CACHE
from src.domain.exceptions.domain_exceptions import EnrichmentError


class DummySettings:
    def __init__(self, value: str):
        self._value = value

    def get(self, key: str, default=None):
        if key.endswith("api_key"):
            return self._value
        return default


@pytest.fixture
def entry():
    SHODAN_CACHE.clear()
    return EnrichableEvent(ip="8.8.8.8")


def test_enrich_success(mocker, entry):
    mocker.patch("config.settings.Settings.get_instance", return_value=DummySettings("SHODANKEY"))
    mock_urlopen = mocker.patch("urllib.request.urlopen")

    response_body = {
        "ports": [22, 80],
        "tags": ["web", "ssh"],
        "asn": "AS15169",
        "os": "Linux",
        "latitude": 37.386,
        "longitude": -122.0838,
    }
    mock_resp = mock_urlopen.return_value.__enter__.return_value
    mock_resp.read.return_value = json.dumps(response_body).encode("utf-8")

    enricher = ShodanEnricherAdapter()
    result = enricher.enrich(entry)

    assert result.enrichments.shodan.asn == "AS15169"
    assert result.enrichments.shodan.os == "Linux"
    assert result.enrichments.shodan.open_ports == [22, 80]
    assert result.enrichments.shodan.tags == ["web", "ssh"]
    assert result.enrichments.shodan.latitude == 37.386
    assert result.enrichments.shodan.longitude == -122.0838


def test_enrich_uses_stale_cache_on_http_429(mocker, entry):
    mocker.patch("config.settings.Settings.get_instance", return_value=DummySettings("SHODANKEY"))
    http_exc = urllib.error.HTTPError(url="", code=429, msg="Too Many Requests", hdrs=None, fp=None)
    mocker.patch("urllib.request.urlopen", side_effect=http_exc)
    SHODAN_CACHE[entry.ip] = {"data": {"open_ports": [443]}, "_ts": FIXED_TS}

    enricher = ShodanEnricherAdapter()
    result = enricher.enrich(entry)

    assert result.enrichments.shodan.open_ports == [443]


def test_enrich_without_api_key_returns_entry(mocker, entry):
    mocker.patch("config.settings.Settings.get_instance", return_value=DummySettings(""))

    result = ShodanEnricherAdapter().enrich(entry)

    assert result is entry
    assert result.enrichments.shodan is None


def test_enrich_uses_fresh_cache_without_api_call(mocker, entry):
    mocker.patch("config.settings.Settings.get_instance", return_value=DummySettings("SHODANKEY"))
    mock_urlopen = mocker.patch("urllib.request.urlopen")
    SHODAN_CACHE[entry.ip] = {
        "data": {"asn": "AS-CACHED", "open_ports": [8080]},
        "_ts": time.time(),
    }

    result = ShodanEnricherAdapter().enrich(entry)

    assert result.enrichments.shodan.asn == "AS-CACHED"
    assert result.enrichments.shodan.open_ports == [8080]
    mock_urlopen.assert_not_called()


def test_enrich_raises_on_http_error_without_stale_cache(mocker, entry):
    mocker.patch("config.settings.Settings.get_instance", return_value=DummySettings("SHODANKEY"))
    http_exc = urllib.error.HTTPError(url="", code=500, msg="Server Error", hdrs=None, fp=None)
    mocker.patch("urllib.request.urlopen", side_effect=http_exc)

    with pytest.raises(EnrichmentError, match="HTTP error 500"):
        ShodanEnricherAdapter().enrich(entry)


def test_enrich_uses_stale_cache_on_generic_api_error(mocker, entry):
    mocker.patch("config.settings.Settings.get_instance", return_value=DummySettings("SHODANKEY"))
    mocker.patch("urllib.request.urlopen", side_effect=OSError("network down"))
    SHODAN_CACHE[entry.ip] = {
        "data": {"tags": ["cached"]},
        "_ts": time.time() - 700,
    }

    result = ShodanEnricherAdapter().enrich(entry)

    assert result.enrichments.shodan.tags == ["cached"]
