"""API tests. All HTTP is faked, so these run offline and use no API quota."""

import unittest

import requests

from ipinfo_app import api

IPAPI_RESPONSE = {
    "ip": "8.8.8.8",
    "network": "8.8.8.0/24",
    "city": "Mountain View",
    "region": "California",
    "country_name": "United States",
    "country_code": "US",
    "latitude": 37.4,
    "longitude": -122.1,
    "timezone": "America/Los_Angeles",
    "asn": "AS15169",
    "org": "GOOGLE",
}

IPWHO_RESPONSE = {
    "success": True,
    "city": "Mountain View",
    "region": "California",
    "country": "United States",
    "country_code": "US",
    "latitude": 37.4,
    "longitude": -122.1,
    "connection": {"asn": 15169, "org": "Google LLC", "isp": "Google LLC"},
    "timezone": {"id": "America/Los_Angeles"},
}


class FakeResponse:
    def __init__(self, payload):
        self.payload = payload

    def raise_for_status(self):
        pass

    def json(self):
        if isinstance(self.payload, Exception):
            raise self.payload
        return self.payload


class FakeSession:
    """Maps a URL prefix to a payload. Unknown URLs or Exceptions fail the call."""

    def __init__(self, routes):
        self.routes = routes
        self.urls = []

    def get(self, url, **kwargs):
        self.urls.append(url)
        for prefix, payload in self.routes.items():
            if url.startswith(prefix):
                if isinstance(payload, requests.RequestException):
                    raise payload
                return FakeResponse(payload)
        raise requests.ConnectionError(f"no route for {url}")


class GetPublicIpTests(unittest.TestCase):
    def test_returns_ipv4(self):
        session = FakeSession({"https://api.ipify.org": {"ip": "8.8.8.8"}})
        self.assertEqual(api.get_public_ip(4, session), "8.8.8.8")

    def test_rejects_wrong_version(self):
        session = FakeSession({"https://api6.ipify.org": {"ip": "8.8.8.8"}})
        with self.assertRaises(api.LookupFailed):
            api.get_public_ip(6, session)

    def test_rejects_malformed_address(self):
        session = FakeSession({"https://api.ipify.org": {"ip": "not-an-ip"}})
        with self.assertRaises(api.LookupFailed):
            api.get_public_ip(4, session)

    def test_rejects_non_json_body(self):
        session = FakeSession({"https://api.ipify.org": ValueError("bad json")})
        with self.assertRaises(api.LookupFailed):
            api.get_public_ip(4, session)


class AnalyseAddressTests(unittest.TestCase):
    def test_scopes(self):
        cases = {
            "8.8.8.8": "global",
            "192.168.1.1": "private",
            "127.0.0.1": "loopback",
            "169.254.1.1": "link-local",
            "224.0.0.1": "multicast",
            "100.64.0.1": "special-use",
            "2001:4860:4860::8888": "global",
            "fd00::1": "private",
            "fe80::1": "link-local",
            "::1": "loopback",
        }
        for address, expected in cases.items():
            with self.subTest(address=address):
                self.assertEqual(api.analyse_address(address)["scope"], expected)

    def test_expands_ipv6(self):
        result = api.analyse_address("2001:db8::1")
        self.assertEqual(result["expanded"], "2001:0db8:0000:0000:0000:0000:0000:0001")
        self.assertEqual(result["version"], 6)


class GetIpDetailsTests(unittest.TestCase):
    def test_uses_first_provider(self):
        session = FakeSession({"https://ipapi.co": IPAPI_RESPONSE})
        details, source = api.get_ip_details("8.8.8.8", session)
        self.assertEqual(source, "ipapi.co")
        self.assertEqual(details["isp"], "GOOGLE")
        self.assertEqual(set(details), set(api.DETAIL_FIELDS))

    def test_falls_back_on_network_error(self):
        session = FakeSession(
            {
                "https://ipapi.co": requests.ConnectionError("down"),
                "https://ipwho.is": IPWHO_RESPONSE,
            }
        )
        details, source = api.get_ip_details("8.8.8.8", session)
        self.assertEqual(source, "ipwho.is")
        self.assertEqual(details["asn"], "AS15169")
        self.assertEqual(details["timezone"], "America/Los_Angeles")
        self.assertEqual(set(details), set(api.DETAIL_FIELDS))

    def test_falls_back_on_api_error_body(self):
        session = FakeSession(
            {
                "https://ipapi.co": {"error": True, "reason": "RateLimited"},
                "https://ipwho.is": IPWHO_RESPONSE,
            }
        )
        self.assertEqual(api.get_ip_details("8.8.8.8", session)[1], "ipwho.is")

    def test_all_providers_failing_raises(self):
        with self.assertRaises(api.LookupFailed):
            api.get_ip_details("8.8.8.8", FakeSession({}))

    def test_invalid_address_never_reaches_a_url(self):
        session = FakeSession({})
        with self.assertRaises(ValueError):
            api.get_ip_details("8.8.8.8/../../admin", session)
        self.assertEqual(session.urls, [])


class ReportTests(unittest.TestCase):
    def test_missing_ipv6_is_reported_not_raised(self):
        report = api.detect_report(6, FakeSession({}))
        self.assertFalse(report.available)
        self.assertIn("IPv6", report.notes[0])

    def test_private_address_makes_no_requests(self):
        session = FakeSession({})
        report = api.build_report("Lookup", "192.168.1.1", session)
        self.assertEqual(session.urls, [])
        self.assertEqual(report.details, {})
        self.assertIn("private", report.notes[0])

    def test_details_failure_keeps_analysis(self):
        report = api.build_report("Lookup", "8.8.8.8", FakeSession({}))
        self.assertTrue(report.available)
        self.assertEqual(report.analysis["scope"], "global")
        self.assertIn("unavailable", report.notes[0])


if __name__ == "__main__":
    unittest.main()
