import json
import time
import urllib.error

import pytest

FIXED_TS = time.time()

from src.domain.models.event import EnrichableEvent
from src.adapters.enrichers.virustotal_enricher_adapter import VirusTotalEnricherAdapter, _CACHE as VT_CACHE
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
    VT_CACHE.clear()
    return EnrichableEvent(ip="8.8.4.4")


def test_enrich_success(mocker, entry):
    mocker.patch("config.settings.Settings.get_instance", return_value=DummySettings("VIRUSTOTALKEY"))
    mock_urlopen = mocker.patch("urllib.request.urlopen")

    response_body = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 5,
                    "suspicious": 2,
                    "harmless": 93,
                    "reputation": 10,
                }
            }
        }
    }
    mock_resp = mock_urlopen.return_value.__enter__.return_value
    mock_resp.read.return_value = json.dumps(response_body).encode("utf-8")

    enricher = VirusTotalEnricherAdapter()
    result = enricher.enrich(entry)

    assert result.enrichments.virustotal.malicious == 5
    assert result.enrichments.virustotal.suspicious == 2
    assert result.enrichments.virustotal.harmless == 93
    assert result.enrichments.virustotal.reputation == 10


def test_enrich_uses_stale_cache_on_http_429(mocker, entry):
    mocker.patch("config.settings.Settings.get_instance", return_value=DummySettings("VIRUSTOTALKEY"))
    http_exc = urllib.error.HTTPError(url="", code=429, msg="Too Many Requests", hdrs=None, fp=None)
    mocker.patch("urllib.request.urlopen", side_effect=http_exc)
    VT_CACHE[entry.ip] = {"data": {"malicious": 1, "suspicious": 0, "harmless": 0, "reputation": 5}, "_ts": FIXED_TS}

    enricher = VirusTotalEnricherAdapter()
    result = enricher.enrich(entry)

    assert result.enrichments.virustotal.malicious == 1
    assert result.enrichments.virustotal.reputation == 5


def test_enrich_without_api_key_returns_entry(mocker, entry):
    mocker.patch("config.settings.Settings.get_instance", return_value=DummySettings(""))

    result = VirusTotalEnricherAdapter().enrich(entry)

    assert result is entry
    assert result.enrichments.virustotal is None


def test_enrich_uses_fresh_cache_without_api_call(mocker, entry):
    mocker.patch("config.settings.Settings.get_instance", return_value=DummySettings("VIRUSTOTALKEY"))
    mock_urlopen = mocker.patch("urllib.request.urlopen")
    VT_CACHE[entry.ip] = {
        "data": {"malicious": 9, "suspicious": 1, "harmless": 10, "reputation": -5},
        "_ts": time.time(),
    }

    result = VirusTotalEnricherAdapter().enrich(entry)

    assert result.enrichments.virustotal.malicious == 9
    assert result.enrichments.virustotal.reputation == -5
    mock_urlopen.assert_not_called()


def test_enrich_raises_on_http_429_without_stale_cache(mocker, entry):
    mocker.patch("config.settings.Settings.get_instance", return_value=DummySettings("VIRUSTOTALKEY"))
    http_exc = urllib.error.HTTPError(url="", code=429, msg="Too Many Requests", hdrs=None, fp=None)
    mocker.patch("urllib.request.urlopen", side_effect=http_exc)

    with pytest.raises(EnrichmentError, match="quota exceeded"):
        VirusTotalEnricherAdapter().enrich(entry)


def test_enrich_raises_on_non_429_http_error_without_stale_cache(mocker, entry):
    mocker.patch("config.settings.Settings.get_instance", return_value=DummySettings("VIRUSTOTALKEY"))
    http_exc = urllib.error.HTTPError(url="", code=500, msg="Server Error", hdrs=None, fp=None)
    mocker.patch("urllib.request.urlopen", side_effect=http_exc)

    with pytest.raises(EnrichmentError, match="HTTP error 500"):
        VirusTotalEnricherAdapter().enrich(entry)


def test_enrich_raises_on_generic_api_error(mocker, entry):
    mocker.patch("config.settings.Settings.get_instance", return_value=DummySettings("VIRUSTOTALKEY"))
    mocker.patch("urllib.request.urlopen", side_effect=OSError("network down"))

    with pytest.raises(EnrichmentError, match="enrichment error"):
        VirusTotalEnricherAdapter().enrich(entry)
