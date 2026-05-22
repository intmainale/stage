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
from src.adapters.enrichers.virustotal_enricher_adapter import VirusTotalEnricherAdapter, _CACHE as VT_CACHE


class DummySettings:
    def __init__(self, value: str):
        self._value = value

    def get(self, key: str, default=None):
        if key.endswith("api_key"):
            return self._value
        return default


class TestVirusTotalEnricherAdapter(unittest.TestCase):

    def setUp(self):
        VT_CACHE.clear()
        self.entry = EnrichableEvent(ip="8.8.4.4")

    @patch("config.settings.Settings.get_instance", return_value=DummySettings("VIRUSTOTALKEY"))
    @patch("urllib.request.urlopen")
    def test_enrich_success(self, mock_urlopen, _):
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
        mock_resp = Mock()
        mock_resp.read.return_value = json.dumps(response_body).encode("utf-8")
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        enricher = VirusTotalEnricherAdapter()
        result = enricher.enrich(self.entry)

        self.assertEqual(result.enrichments.virustotal.malicious, 5)
        self.assertEqual(result.enrichments.virustotal.suspicious, 2)
        self.assertEqual(result.enrichments.virustotal.harmless, 93)
        self.assertEqual(result.enrichments.virustotal.reputation, 10)

    @patch("config.settings.Settings.get_instance", return_value=DummySettings("VIRUSTOTALKEY"))
    @patch("urllib.request.urlopen")
    def test_enrich_uses_stale_cache_on_http_429(self, mock_urlopen, _):
        VT_CACHE[self.entry.ip] = {"data": {"malicious": 1, "suspicious": 0, "harmless": 0, "reputation": 5}, "_ts": time.time()}
        http_exc = urllib.error.HTTPError(url="", code=429, msg="Too Many Requests", hdrs=None, fp=None)
        mock_urlopen.side_effect = http_exc

        enricher = VirusTotalEnricherAdapter()
        result = enricher.enrich(self.entry)

        self.assertEqual(result.enrichments.virustotal.malicious, 1)
        self.assertEqual(result.enrichments.virustotal.reputation, 5)

    @patch("config.settings.Settings.get_instance", return_value=DummySettings(""))
    def test_enrich_without_api_key_returns_entry(self, _):
        enricher = VirusTotalEnricherAdapter()
        result = enricher.enrich(self.entry)
        self.assertIs(result, self.entry)
        self.assertIsNone(result.enrichments.virustotal)


class DummySettings:
    def __init__(self, value: str):
        self._value = value

    def get(self, key: str, default=None):
        if key.endswith("api_key"):
            return self._value
        return default


class TestVirusTotalEnricherAdapter(unittest.TestCase):

    def setUp(self):
        VT_CACHE.clear()
        self.entry = EnrichableEvent(ip="8.8.4.4")

    @patch("config.settings.Settings.get_instance", return_value=DummySettings("VIRUSTOTALKEY"))
    @patch("urllib.request.urlopen")
    def test_enrich_success(self, mock_urlopen, _):
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
        mock_resp = Mock()
        mock_resp.read.return_value = json.dumps(response_body).encode("utf-8")
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        enricher = VirusTotalEnricherAdapter()
        result = enricher.enrich(self.entry)

        self.assertEqual(result.enrichments.virustotal.malicious, 5)
        self.assertEqual(result.enrichments.virustotal.suspicious, 2)
        self.assertEqual(result.enrichments.virustotal.harmless, 93)
        self.assertEqual(result.enrichments.virustotal.reputation, 10)

    @patch("config.settings.Settings.get_instance", return_value=DummySettings(""))
    def test_enrich_without_api_key_returns_entry(self, _):
        enricher = VirusTotalEnricherAdapter()
        result = enricher.enrich(self.entry)
        self.assertIs(result, self.entry)
        self.assertIsNone(result.enrichments.virustotal)


if __name__ == "__main__":
    unittest.main()
