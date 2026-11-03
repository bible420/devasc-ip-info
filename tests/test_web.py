"""Web dashboard tests. All HTTP to the providers is faked, so these run offline."""

import json
import unittest

from ipinfo_app import api, display
from ipinfo_app.web import create_app
from tests.test_api import IPAPI_RESPONSE, IPWHO_RESPONSE, FakeSession

OWN_IP = "9.9.9.9"
OWN_DETAILS = {**IPAPI_RESPONSE, "city": "Exampleville", "region": "Example Region", "network": "9.9.9.0/24"}
ROUTES = {
    "https://api.ipify.org": {"ip": OWN_IP},
    "https://ipapi.co": OWN_DETAILS,
    "https://ipwho.is": {**IPWHO_RESPONSE, "city": "Otherville"},
}


def client_for(routes):
    session = FakeSession(routes)
    return create_app(session=session).test_client(), session


class BitTests(unittest.TestCase):
    def test_ipv4_groups(self):
        self.assertEqual(
            display.address_bits("8.8.4.1"),
            ["00001000", "00001000", "00000100", "00000001"],
        )

    def test_ipv6_has_eight_groups_of_sixteen(self):
        groups = display.address_bits("2001:db8::1")
        self.assertEqual([len(group) for group in groups], [16] * 8)
        self.assertEqual(groups[0], "0010000000000001")

    def test_masked_bits_match_masked_address(self):
        self.assertEqual(
            display.address_bits("8.8.4.1", masked=True),
            ["00001000", "00001000", "xxxxxxxx", "xxxxxxxx"],
        )
        groups = display.address_bits("2001:db8::1", masked=True)
        self.assertEqual(groups[1], "0000110110111000")
        self.assertEqual(groups[2:], ["x" * 16] * 6)


class CompareTests(unittest.TestCase):
    def compare(self, routes):
        return api.compare_providers("8.8.8.8", FakeSession(routes))

    def rows(self, result):
        return {row["field"]: row for row in result["rows"]}

    def test_reports_matches_differences_and_distance(self):
        result = self.compare(
            {
                "https://ipapi.co": IPAPI_RESPONSE,
                "https://ipwho.is": {
                    **IPWHO_RESPONSE,
                    "city": "San Jose",
                    "latitude": 37.4,
                    "longitude": -121.1,
                },
            }
        )
        rows = self.rows(result)
        self.assertEqual(rows["asn"]["status"], "match")
        self.assertEqual(rows["city"]["status"], "differs")
        self.assertEqual(rows["network"]["status"], "partial")  # only ipapi.co has it
        self.assertEqual(rows["country_code"]["status"], "match")
        self.assertEqual(result["distance_km"], 88)

    def test_comparison_ignores_case(self):
        result = self.compare(
            {
                "https://ipapi.co": {**IPAPI_RESPONSE, "org": "GOOGLE LLC"},
                "https://ipwho.is": IPWHO_RESPONSE,
            }
        )
        self.assertEqual(self.rows(result)["isp"]["status"], "match")

    def test_one_failed_provider(self):
        result = self.compare({"https://ipwho.is": IPWHO_RESPONSE})
        self.assertEqual(result["providers"], ["ipwho.is"])
        self.assertEqual(result["failed"], ["ipapi.co"])
        self.assertIsNone(result["distance_km"])
        self.assertTrue(all(row["status"] == "partial" for row in result["rows"]))

    def test_all_providers_failed(self):
        result = self.compare({})
        self.assertEqual(result["providers"], [])
        self.assertIsNone(result["distance_km"])


class RouteTests(unittest.TestCase):
    def test_page_loads(self):
        client, session = client_for({})
        response = client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Address Bench", response.data)
        self.assertEqual(session.urls, [])

    def test_lookup_returns_bits_and_prefix(self):
        client, _ = client_for(ROUTES)
        data = client.get("/api/lookup?ip=8.8.8.8").get_json()
        self.assertEqual(data["report"]["address"], "8.8.8.8")
        self.assertEqual(data["prefix_length"], 24)
        self.assertEqual(len(data["bits"]), 4)

    def test_invalid_lookup_makes_no_requests(self):
        client, session = client_for(ROUTES)
        for value in ("nope", "", "8.8.8.8/../admin", "<script>"):
            with self.subTest(value=value):
                response = client.get("/api/lookup", query_string={"ip": value})
                self.assertEqual(response.status_code, 400)
                self.assertIn("error", response.get_json())
        self.assertEqual(session.urls, [])

    def test_private_lookup_makes_no_requests(self):
        client, session = client_for(ROUTES)
        data = client.get("/api/lookup?ip=10.0.0.1").get_json()
        self.assertEqual(data["report"]["analysis"]["scope"], "private")
        self.assertEqual(session.urls, [])

    def test_missing_ipv6_is_a_normal_response(self):
        client, _ = client_for(ROUTES)
        response = client.get("/api/detect?version=6")
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.get_json()["report"]["available"])

    def test_invalid_version_is_rejected(self):
        client, session = client_for(ROUTES)
        self.assertEqual(client.get("/api/detect?version=5").status_code, 400)
        self.assertEqual(client.get("/api/crosscheck?version=5").status_code, 400)
        self.assertEqual(session.urls, [])

    def test_crosscheck_private_address_makes_no_requests(self):
        client, session = client_for(ROUTES)
        response = client.get("/api/crosscheck?ip=192.168.1.1")
        self.assertEqual(response.status_code, 422)
        self.assertEqual(session.urls, [])

    def test_crosscheck_without_detected_address(self):
        client, _ = client_for({})
        self.assertEqual(client.get("/api/crosscheck?version=4").status_code, 503)

    def test_foreign_host_is_rejected(self):
        client, session = client_for(ROUTES)
        response = client.get("/api/detect?version=4", headers={"Host": "evil.example"})
        self.assertEqual(response.status_code, 403)
        self.assertEqual(session.urls, [])

    def test_localhost_is_accepted(self):
        client, _ = client_for(ROUTES)
        for host in ("localhost:5000", "127.0.0.1:5000"):
            with self.subTest(host=host):
                self.assertEqual(client.get("/", headers={"Host": host}).status_code, 200)

    def test_security_headers(self):
        client, _ = client_for(ROUTES)
        headers = client.get("/").headers
        self.assertEqual(headers["Content-Security-Policy"], "default-src 'self'")
        self.assertEqual(headers["Cache-Control"], "no-store")


class MaskRouteTests(unittest.TestCase):
    """A masked response must not contain identifying values anywhere."""

    SECRETS = ("9.9.9", "Exampleville", "Example Region", "Otherville", "37.4", "-122.1", "-121")

    def assert_no_secrets(self, data):
        text = json.dumps(data)
        for secret in self.SECRETS:
            self.assertNotIn(secret, text)

    def test_detect(self):
        client, _ = client_for(ROUTES)
        data = client.get("/api/detect?version=4&mask=1").get_json()
        self.assert_no_secrets(data)
        self.assertEqual(data["report"]["address"], "9.9.xxx.xxx")
        self.assertEqual(data["bits"][2:], ["x" * 8, "x" * 8])
        self.assertIsNone(data["prefix_length"])
        self.assertTrue(data["masked"])

    def test_crosscheck_keeps_status_but_hides_values(self):
        client, _ = client_for(ROUTES)
        data = client.get("/api/crosscheck?version=4&mask=1").get_json()
        self.assert_no_secrets(data)
        city = next(row for row in data["rows"] if row["field"] == "city")
        self.assertEqual(city["status"], "differs")
        self.assertEqual(set(city["values"].values()), {"(masked)"})


if __name__ == "__main__":
    unittest.main()
