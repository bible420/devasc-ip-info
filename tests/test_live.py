"""Live tests against the real APIs. Skipped unless RUN_LIVE_TESTS=1.

The unit tests fake every HTTP response, so they can't notice a provider
changing its response format. These tests call the real services instead. They
run every day in GitHub Actions (.github/workflows/live-check.yml), and can be
run locally with:

    RUN_LIVE_TESTS=1 python -m unittest tests.test_live -v
"""

import contextlib
import io
import json
import os
import unittest

import requests

from ipinfo_app import __main__ as cli
from ipinfo_app import api

LIVE = os.environ.get("RUN_LIVE_TESTS") == "1"
TIMEOUT = 15  # seconds; generous, because CI runners can be slow
GOOGLE_DNS = "8.8.8.8"

# A provider that is only rate limiting is not broken, so those tests are skipped.
RATE_LIMIT_SIGNS = ("429", "Too Many Requests", "RateLimited")


@unittest.skipUnless(LIVE, "set RUN_LIVE_TESTS=1 to call the real APIs")
class LiveApiTests(unittest.TestCase):
    def test_detects_public_ipv4(self):
        address = api.get_public_ip(4, timeout=TIMEOUT)
        self.assertEqual(api.analyse_address(address)["version"], 4)

    def test_each_provider_still_returns_expected_fields(self):
        """Fails if a provider renames or removes a field the app depends on."""
        for name, url_template, parser in api.PROVIDERS:
            with self.subTest(provider=name):
                try:
                    data = api._get_json(url_template.format(ip=GOOGLE_DNS), requests, TIMEOUT)
                    details = parser(data)
                except api.LookupFailed as exc:
                    if any(sign in str(exc) for sign in RATE_LIMIT_SIGNS):
                        self.skipTest(f"{name} is rate limiting this runner")
                    raise
                self.assertEqual(set(details), set(api.DETAIL_FIELDS))
                self.assertEqual(details["asn"], "AS15169")
                self.assertEqual(details["country_code"], "US")
                self.assertTrue(details["isp"])

    def test_full_lookup_from_the_command_line(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = cli.main(["-l", GOOGLE_DNS, "--json", "--timeout", str(TIMEOUT)])
        self.assertEqual(code, 0)
        report = json.loads(out.getvalue())[0]
        self.assertEqual(report["address"], GOOGLE_DNS)
        self.assertEqual(report["details"].get("asn"), "AS15169", report["notes"])


if __name__ == "__main__":
    unittest.main()
