import json
import os
import sys
import time
import urllib.error
import unittest
from unittest.mock import Mock, patch
from pathlib import Path

# Add project root to path for real src imports
PROJECT_ROOT = Path(__file__).resolve().parents[5]
sys.path.insert(0, str(PROJECT_ROOT))

from src.domain.models.event import EnrichableEvent
from src.adapters.enrichers.shodan_enricher_adapter import ShodanEnricherAdapter, _CACHE as SHODAN_CACHE


class DummySettings:
    def __init__(self, value: str):
        self._value = value

    def get(self, key: str, default=None):
        if key.endswith("api_key"):
            return self._value
        return default


class TestShodanEnricherAdapter(unittest.TestCase):

    def setUp(self):
        SHODAN_CACHE.clear()
        self.entry = EnrichableEvent(ip="8.8.8.8")

    @patch("config.settings.Settings.get_instance", return_value=DummySettings("SHODANKEY"))
    @patch("urllib.request.urlopen")
    def test_enrich_success(self, mock_urlopen, _):
        response_body = {
            "ports": [22, 80],
            "tags": ["web", "ssh"],
            "asn": "AS15169",
            "os": "Linux",
            "latitude": 37.386,
            "longitude": -122.0838,
        }
        mock_resp = Mock()
        mock_resp.read.return_value = json.dumps(response_body).encode("utf-8")
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        enricher = ShodanEnricherAdapter()
        result = enricher.enrich(self.entry)

        self.assertEqual(result.enrichments.shodan.asn, "AS15169")
        self.assertEqual(result.enrichments.shodan.os, "Linux")
        self.assertEqual(result.enrichments.shodan.open_ports, [22, 80])
        self.assertEqual(result.enrichments.shodan.tags, ["web", "ssh"])

    @patch("config.settings.Settings.get_instance", return_value=DummySettings("SHODANKEY"))
    @patch("urllib.request.urlopen")
    def test_enrich_uses_stale_cache_on_http_429(self, mock_urlopen, _):
        SHODAN_CACHE[self.entry.ip] = {"data": {"ports": [443]}, "_ts": time.time()}
        http_exc = urllib.error.HTTPError(url="", code=429, msg="Too Many Requests", hdrs=None, fp=None)
        mock_urlopen.side_effect = http_exc

        enricher = ShodanEnricherAdapter()
        result = enricher.enrich(self.entry)

        self.assertEqual(result.enrichments.shodan.open_ports, [443])

    @patch("config.settings.Settings.get_instance", return_value=DummySettings(""))
    def test_enrich_without_api_key_returns_entry(self, _):
        enricher = ShodanEnricherAdapter()
        result = enricher.enrich(self.entry)
        self.assertIs(result, self.entry)
        self.assertIsNone(result.enrichments.shodan)


class DummySettings:
    def __init__(self, value: str):
        self._value = value

    def get(self, key: str, default=None):
        if key.endswith("api_key"):
            return self._value
        return default


class TestShodanEnricherAdapter(unittest.TestCase):

    def setUp(self):
        SHODAN_CACHE.clear()
        self.entry = EnrichableEvent(ip="8.8.8.8")

    @patch("config.settings.Settings.get_instance", return_value=DummySettings("SHODANKEY"))
    @patch("urllib.request.urlopen")
    def test_enrich_success(self, mock_urlopen, _):
        response_body = {
            "ports": [22, 80],
            "tags": ["web", "ssh"],
            "asn": "AS15169",
            "os": "Linux",
            "latitude": 37.386,
            "longitude": -122.0838,
        }
        mock_resp = Mock()
        mock_resp.read.return_value = json.dumps(response_body).encode("utf-8")
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        enricher = ShodanEnricherAdapter()
        result = enricher.enrich(self.entry)

        self.assertEqual(result.enrichments.shodan.asn, "AS15169")
        self.assertEqual(result.enrichments.shodan.os, "Linux")
        self.assertEqual(result.enrichments.shodan.open_ports, [22, 80])
        self.assertEqual(result.enrichments.shodan.tags, ["web", "ssh"])

    @patch("config.settings.Settings.get_instance", return_value=DummySettings(""))
    def test_enrich_without_api_key_returns_entry(self, _):
        enricher = ShodanEnricherAdapter()
        result = enricher.enrich(self.entry)
        self.assertIs(result, self.entry)
        self.assertIsNone(result.enrichments.shodan)


if __name__ == "__main__":
    unittest.main()
