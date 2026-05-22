import json
import os
import sys
import time
import unittest
import urllib.error
from unittest.mock import Mock, patch
from pathlib import Path

# Add project root to path for real src imports
PROJECT_ROOT = Path(__file__).resolve().parents[5]
sys.path.insert(0, str(PROJECT_ROOT))

from src.domain.models.event import EnrichableEvent
from src.adapters.enrichers.abuseipdb_enricher_adapter import AbuseIPDBEnricherAdapter, _CACHE as ABUSE_CACHE


class DummySettings:
    def __init__(self, value: str):
        self._value = value

    def get(self, key: str, default=None):
        if key.endswith("api_key"):
            return self._value
        return default


class TestAbuseIPDBEnricherAdapter(unittest.TestCase):

    def setUp(self):
        ABUSE_CACHE.clear()
        self.entry = EnrichableEvent(ip="1.2.3.4")

    @patch("config.settings.Settings.get_instance", return_value=DummySettings("KEY123"))
    @patch("urllib.request.urlopen")
    def test_enrich_success(self, mock_urlopen, _):
        response_body = {
            "data": {
                "abuseConfidenceScore": 85,
                "totalReports": 12,
                "countryName": "US",
                "isp": "Example ISP",
                "usageType": "Data Center",
            }
        }
        mock_resp = Mock()
        mock_resp.read.return_value = json.dumps(response_body).encode("utf-8")
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        enricher = AbuseIPDBEnricherAdapter()
        result = enricher.enrich(self.entry)

        self.assertEqual(result.enrichments.abuseipdb.abuse_confidence_score, 85)
        self.assertEqual(result.enrichments.abuseipdb.total_reports, 12)
        self.assertEqual(result.enrichments.abuseipdb.country, "US")
        self.assertEqual(result.enrichments.abuseipdb.isp, "Example ISP")
        self.assertEqual(result.enrichments.abuseipdb.usage_type, "Data Center")

    @patch("config.settings.Settings.get_instance", return_value=DummySettings("KEY123"))
    @patch("urllib.request.urlopen")
    @patch("time.time", return_value=1_000_000.0)
    def test_enrich_http_429_uses_stale_cache(self, mock_time, mock_urlopen, _):
        ABUSE_CACHE["1.2.3.4"] = {"data": {"abuse_confidence_score": 77}, "_ts": 1_000_000.0 - 3_500}
        http_exc = urllib.error.HTTPError(url="", code=429, msg="Too Many Requests", hdrs=None, fp=None)
        mock_urlopen.side_effect = http_exc

        enricher = AbuseIPDBEnricherAdapter()
        result = enricher.enrich(self.entry)

        self.assertEqual(result.enrichments.abuseipdb.abuse_confidence_score, 77)

    @patch("config.settings.Settings.get_instance", return_value=DummySettings(""))
    def test_enrich_without_api_key_returns_entry(self, _):
        enricher = AbuseIPDBEnricherAdapter()
        result = enricher.enrich(self.entry)
        self.assertIs(result, self.entry)
        self.assertIsNone(result.enrichments.abuseipdb)


if __name__ == "__main__":
    unittest.main()
