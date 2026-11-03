"""REST API access and address analysis. This module does no printing.

Data flow:
    detect_report(version)  -> get_public_ip() -> build_report()
    build_report(address)   -> analyse_address() + get_ip_details()

To add a details provider, write a parser that returns the DETAIL_FIELDS keys
and add it to PROVIDERS. Providers are tried in order until one succeeds.
"""

from dataclasses import dataclass, field
import ipaddress

import requests

from . import __version__

DEFAULT_TIMEOUT = 5  # seconds, applied to each HTTP request

# ipify publishes a separate hostname per IP version. api6 only has an AAAA
# DNS record, so it fails on a network without IPv6 connectivity.
DETECT_URLS = {
    4: "https://api.ipify.org",
    6: "https://api6.ipify.org",
}

HEADERS = {"User-Agent": f"devasc-ip-info/{__version__}"}

# Every provider parser returns exactly these keys (None when unknown).
DETAIL_FIELDS = (
    "isp",
    "asn",
    "network",
    "city",
    "region",
    "country",
    "country_code",
    "latitude",
    "longitude",
    "timezone",
)


class LookupFailed(Exception):
    """A REST API could not be reached or returned unusable data."""


@dataclass
class IPReport:
    """Everything known about one address. Display and JSON both use this."""

    label: str
    available: bool
    address: str | None = None
    analysis: dict = field(default_factory=dict)
    details: dict = field(default_factory=dict)
    source: str | None = None
    notes: list = field(default_factory=list)


def _get_json(url, session, timeout, params=None):
    """GET a URL and return its JSON object, or raise LookupFailed."""
    try:
        response = session.get(url, params=params, headers=HEADERS, timeout=timeout)
        response.raise_for_status()
        data = response.json()
    except (requests.RequestException, ValueError) as exc:
        # requests' JSON errors subclass ValueError, so both cases land here.
        raise LookupFailed(f"{url}: {exc}") from exc
    if not isinstance(data, dict):
        raise LookupFailed(f"{url}: expected a JSON object")
    return data


def get_public_ip(version, session=requests, timeout=DEFAULT_TIMEOUT):
    """Return this computer's public IP for the given version (4 or 6)."""
    data = _get_json(DETECT_URLS[version], session, timeout, {"format": "json"})
    try:
        address = ipaddress.ip_address(data.get("ip", ""))
    except ValueError as exc:
        raise LookupFailed(f"invalid address from API: {data.get('ip')!r}") from exc
    if address.version != version:
        raise LookupFailed(f"expected IPv{version}, API returned {address}")
    return str(address)


def analyse_address(address):
    """Describe an address using only the standard library (no network)."""
    ip = ipaddress.ip_address(address)
    return {
        "version": ip.version,
        "compressed": ip.compressed,
        "expanded": ip.exploded,
        "scope": _scope(ip),
        "reverse_dns_name": ip.reverse_pointer,
    }


def _scope(ip):
    # Order matters: ipaddress also reports most of these ranges as is_private.
    checks = (
        ("loopback", ip.is_loopback),
        ("link-local", ip.is_link_local),
        ("multicast", ip.is_multicast),
        ("unspecified", ip.is_unspecified),
        ("reserved", ip.is_reserved),
        ("private", ip.is_private),
        ("global", ip.is_global),
    )
    return next((name for name, matched in checks if matched), "special-use")


def _parse_ipapi_co(data):
    """Map an ipapi.co response onto DETAIL_FIELDS."""
    if data.get("error"):
        raise LookupFailed(f"ipapi.co: {data.get('reason', 'unknown error')}")
    return {
        "isp": data.get("org"),
        "asn": data.get("asn"),
        "network": data.get("network"),
        "city": data.get("city"),
        "region": data.get("region"),
        "country": data.get("country_name"),
        "country_code": data.get("country_code"),
        "latitude": data.get("latitude"),
        "longitude": data.get("longitude"),
        "timezone": data.get("timezone"),
    }


def _parse_ipwho_is(data):
    """Map an ipwho.is response onto DETAIL_FIELDS."""
    if data.get("success") is False:
        raise LookupFailed(f"ipwho.is: {data.get('message', 'unknown error')}")
    connection = data.get("connection") or {}
    asn = connection.get("asn")
    return {
        "isp": connection.get("isp") or connection.get("org"),
        "asn": f"AS{asn}" if asn else None,  # ipwho.is returns a bare number
        "network": None,  # not provided by this API
        "city": data.get("city"),
        "region": data.get("region"),
        "country": data.get("country"),
        "country_code": data.get("country_code"),
        "latitude": data.get("latitude"),
        "longitude": data.get("longitude"),
        "timezone": (data.get("timezone") or {}).get("id"),
    }


# (name, URL template, parser). ipapi.co goes first because it includes the
# network prefix; ipwho.is is the fallback when ipapi.co is rate limiting.
PROVIDERS = (
    ("ipapi.co", "https://ipapi.co/{ip}/json/", _parse_ipapi_co),
    ("ipwho.is", "https://ipwho.is/{ip}", _parse_ipwho_is),
)


def get_ip_details(address, session=requests, timeout=DEFAULT_TIMEOUT):
    """Return (details, provider name) from the first provider that works.

    The address is re-validated here so that only a real IP is ever placed
    in a request URL.
    """
    address = str(ipaddress.ip_address(address))
    errors = []
    for name, url_template, parser in PROVIDERS:
        try:
            data = _get_json(url_template.format(ip=address), session, timeout)
            return parser(data), name
        except LookupFailed as exc:
            errors.append(str(exc))
    raise LookupFailed("; ".join(errors))


def build_report(label, address, session=requests, timeout=DEFAULT_TIMEOUT):
    """Build a report. A details failure still returns the address analysis."""
    report = IPReport(label, True, str(ipaddress.ip_address(address)))
    report.analysis = analyse_address(address)
    scope = report.analysis["scope"]
    if scope != "global":
        report.notes.append(f"No ISP or location data: this is a {scope} address.")
        return report
    try:
        report.details, report.source = get_ip_details(address, session, timeout)
    except LookupFailed:
        report.notes.append(
            "ISP and location data unavailable: all providers failed. Try again later."
        )
    return report


def detect_report(version, session=requests, timeout=DEFAULT_TIMEOUT):
    """Build a report for this computer's public address, if it has one."""
    label = f"Public IPv{version}"
    try:
        address = get_public_ip(version, session, timeout)
    except LookupFailed:
        return IPReport(
            label,
            False,
            notes=[
                f"No public IPv{version} address detected. The network may not "
                f"support IPv{version}, or the service may be unreachable."
            ],
        )
    return build_report(label, address, session, timeout)
