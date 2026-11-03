"""Web dashboard: python -m ipinfo_app.web, then open the printed address.

This is a thin layer. Lookups come from api.py and masking from display.py, so
the dashboard and the command-line tool always behave the same way. The page
itself is in templates/index.html and static/.

The server only listens on this computer and only accepts requests addressed
to localhost, so other websites and devices can't read a technician's results.
"""

import argparse
from dataclasses import asdict
import ipaddress
from pathlib import Path
import webbrowser

from flask import Flask, abort, jsonify, render_template, request
import requests

from .api import (
    DEFAULT_TIMEOUT,
    LookupFailed,
    analyse_address,
    build_report,
    compare_providers,
    detect_report,
    get_public_ip,
)
from .display import address_bits, mask_comparison, mask_report

ALLOWED_HOSTS = {"127.0.0.1", "localhost"}


def _prefix_length(report):
    """Return the prefix length from a report's network, such as 24, if known."""
    try:
        return ipaddress.ip_network(report.details.get("network"), strict=False).prefixlen
    except (TypeError, ValueError):
        return None


def report_payload(report, mask):
    """Build the JSON for one report. All masking happens here, on the server."""
    if not report.available:
        return {"report": asdict(report), "bits": None, "prefix_length": None, "masked": False}
    prefix = None if mask else _prefix_length(report)
    bits = address_bits(report.address, masked=mask)
    shown = mask_report(report) if mask else report
    return {"report": asdict(shown), "bits": bits, "prefix_length": prefix, "masked": mask}


def create_app(session=requests, timeout=DEFAULT_TIMEOUT):
    """Create the app. Tests pass a fake session so that no real requests are made."""
    app = Flask(__name__, root_path=str(Path(__file__).parent))

    def wants_mask():
        return request.args.get("mask") == "1"

    def valid_ip_argument():
        try:
            return str(ipaddress.ip_address(request.args.get("ip", "").strip()))
        except ValueError:
            abort(400, description="Enter a valid IPv4 or IPv6 address.")

    def valid_version_argument():
        version = request.args.get("version")
        if version not in ("4", "6"):
            abort(400, description="version must be 4 or 6.")
        return int(version)

    @app.before_request
    def reject_foreign_hosts():
        # Blocks DNS rebinding, where a malicious site points its own name at
        # 127.0.0.1 to read this server's responses.
        if request.host.rsplit(":", 1)[0] not in ALLOWED_HOSTS:
            abort(403, description="This dashboard only accepts local requests.")

    @app.after_request
    def add_security_headers(response):
        response.headers["Content-Security-Policy"] = "default-src 'self'"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.errorhandler(400)
    @app.errorhandler(403)
    def json_error(error):
        return jsonify(error=error.description), error.code

    @app.get("/")
    def index():
        return render_template("index.html")

    @app.get("/api/detect")
    def detect():
        version = valid_version_argument()
        return jsonify(report_payload(detect_report(version, session, timeout), wants_mask()))

    @app.get("/api/lookup")
    def lookup():
        address = valid_ip_argument()
        label = f"Lookup: IPv{ipaddress.ip_address(address).version}"
        return jsonify(report_payload(build_report(label, address, session, timeout), wants_mask()))

    @app.get("/api/crosscheck")
    def crosscheck():
        # The page may only hold a masked address, so for this computer's own
        # address it sends the IP version and the server detects it again.
        if "ip" in request.args:
            address = valid_ip_argument()
        else:
            try:
                address = get_public_ip(valid_version_argument(), session, timeout)
            except LookupFailed:
                return jsonify(error="The public address could not be detected."), 503
        scope = analyse_address(address)["scope"]
        if scope != "global":
            return jsonify(error=f"Providers have no records for a {scope} address."), 422
        comparison = compare_providers(address, session, timeout)
        return jsonify(mask_comparison(comparison) if wants_mask() else comparison)

    return app


def main():
    parser = argparse.ArgumentParser(
        prog="python -m ipinfo_app.web", description="Run the local web dashboard."
    )
    parser.add_argument("--port", type=int, default=5000, help="port to use (default: 5000)")
    parser.add_argument("--no-browser", action="store_true", help="don't open a browser")
    args = parser.parse_args()

    url = f"http://127.0.0.1:{args.port}"
    print(f"Dashboard running at {url} (press Ctrl+C to stop)")
    if not args.no_browser:
        webbrowser.open(url)
    create_app().run(host="127.0.0.1", port=args.port)


if __name__ == "__main__":
    main()
