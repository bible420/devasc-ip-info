"""Display and command-line tests. No network access."""

import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from ipinfo_app import __main__ as cli
from ipinfo_app import api, display

DETAILS = {
    "isp": "Example ISP",
    "asn": "AS64500",
    "network": "203.0.113.0/24",
    "city": "Exampleville",
    "region": "Example Region",
    "country": "Exampleland",
    "country_code": "EX",
    "latitude": 1.5,
    "longitude": 2.5,
    "timezone": "UTC",
}


def sample_report():
    report = api.IPReport("Public IPv4", True, "203.0.113.7")
    report.analysis = api.analyse_address("203.0.113.7")
    report.details = dict(DETAILS)
    report.source = "ipapi.co"
    return report


class MaskTests(unittest.TestCase):
    def test_mask_address(self):
        self.assertEqual(display.mask_address("203.0.113.7"), "203.0.xxx.xxx")
        self.assertEqual(
            display.mask_address("2001:db8::1"),
            "2001:0db8:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx",
        )

    def test_mask_hides_identifying_values_everywhere(self):
        masked = display.mask_report(sample_report())
        output = display.render_table(masked, color=False) + display.render_json([masked])
        for secret in ("203.0.113", "113.0.203", "Exampleville", "Example Region", "1.5", "2.5"):
            self.assertNotIn(secret, output)
        self.assertIn("Example ISP", output)

    def test_mask_leaves_original_unchanged(self):
        report = sample_report()
        display.mask_report(report)
        self.assertEqual(report.address, "203.0.113.7")
        self.assertEqual(report.details["city"], "Exampleville")


class RenderTests(unittest.TestCase):
    def test_table_rows_have_equal_width(self):
        lines = display.render_table(sample_report(), color=False).splitlines()[1:]
        self.assertEqual(len({len(line) for line in lines}), 1)

    def test_no_color_has_no_escape_codes(self):
        self.assertNotIn("\033", display.render_table(sample_report(), color=False))

    def test_color_keeps_table_alignment(self):
        plain = display.render_table(sample_report(), color=False)
        colored = display.render_table(sample_report(), color=True)
        self.assertIn("\033", colored)
        for code in (display.GREEN, display.CYAN, display.BOLD, display.RESET):
            colored = colored.replace(code, "")
        self.assertEqual(colored, plain)

    def test_unavailable_report(self):
        report = api.IPReport("Public IPv6", False, notes=["No IPv6."])
        output = display.render_table(report, color=False)
        self.assertIn("Not available", output)
        self.assertIn("No IPv6.", output)

    def test_json_is_valid(self):
        data = json.loads(display.render_json([sample_report()]))
        self.assertEqual(data[0]["address"], "203.0.113.7")


class CliTests(unittest.TestCase):
    def run_main(self, argv):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = cli.main(argv)
        return code, out.getvalue()

    def assert_usage_error(self, argv):
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as caught:
                cli.parse_args(argv)
        self.assertEqual(caught.exception.code, 2)

    def test_invalid_arguments_are_rejected(self):
        for argv in (
            ["--lookup", "not-an-ip"],
            ["--lookup", "8.8.8.8", "-4"],
            ["-4", "-6"],
            ["--timeout", "0"],
        ):
            with self.subTest(argv=argv):
                self.assert_usage_error(argv)

    def test_private_lookup_runs_offline(self):
        code, output = self.run_main(["--lookup", "10.0.0.1", "--no-color"])
        self.assertEqual(code, 0)
        self.assertIn("10.0.0.1", output)
        self.assertIn("private", output)

    def test_default_detects_both_versions(self):
        with mock.patch.object(cli, "detect_report") as detect:
            detect.side_effect = lambda version, timeout: api.IPReport(
                f"Public IPv{version}", False
            )
            code, _ = self.run_main(["--no-color"])
        self.assertEqual([call.args[0] for call in detect.call_args_list], [4, 6])
        self.assertEqual(code, 1)

    def test_ipv4_only(self):
        with mock.patch.object(cli, "detect_report") as detect:
            detect.return_value = sample_report()
            code, _ = self.run_main(["-4", "--no-color"])
        detect.assert_called_once()
        self.assertEqual(code, 0)


class SaveReportTests(unittest.TestCase):
    """--output saves a JSON report. Uses a temporary folder and no network."""

    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.folder = Path(folder.name)

    def run_main(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(argv)
        return code, out.getvalue(), err.getvalue()

    def test_saves_report_with_metadata(self):
        path = self.folder / "report.json"
        code, _, err = self.run_main(["-l", "10.0.0.1", "--no-color", "-o", str(path)])
        self.assertEqual(code, 0)
        self.assertIn("Report saved to", err)
        data = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(data["reports"][0]["address"], "10.0.0.1")
        self.assertEqual(data["app_version"], cli.__version__)
        self.assertIn("T", data["generated_at"])

    def test_saved_report_is_masked_with_mask(self):
        path = self.folder / "masked.json"
        with mock.patch.object(cli, "detect_report", return_value=sample_report()):
            self.run_main(["-4", "--mask", "--no-color", "-o", str(path)])
        text = path.read_text(encoding="utf-8")
        for secret in ("203.0.113", "Exampleville", "Example Region"):
            self.assertNotIn(secret, text)
        self.assertIn("203.0.xxx.xxx", text)

    def test_json_on_screen_stays_valid(self):
        path = self.folder / "report.json"
        _, out, _ = self.run_main(["-l", "10.0.0.1", "--json", "-o", str(path)])
        self.assertEqual(json.loads(out)[0]["address"], "10.0.0.1")

    def test_replaces_existing_file(self):
        path = self.folder / "report.json"
        path.write_text("old", encoding="utf-8")
        self.run_main(["-l", "10.0.0.1", "--no-color", "-o", str(path)])
        self.assertNotIn("old", path.read_text(encoding="utf-8"))

    def test_unwritable_path_returns_error(self):
        path = self.folder / "missing-folder" / "report.json"
        code, _, err = self.run_main(["-l", "10.0.0.1", "--no-color", "-o", str(path)])
        self.assertEqual(code, 2)
        self.assertIn("Could not save the report", err)
        self.assertFalse(path.exists())


if __name__ == "__main__":
    unittest.main()
