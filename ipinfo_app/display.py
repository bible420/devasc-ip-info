"""Turn IPReport objects into terminal tables or JSON. No network access."""

from dataclasses import asdict, replace
import ipaddress
import json

from . import __version__

GREEN, YELLOW, CYAN, BOLD, RESET = (
    "\033[32m",
    "\033[33m",
    "\033[36m",
    "\033[1m",
    "\033[0m",
)

# (table label, section of the report, key). Empty values are skipped.
ROWS = (
    ("Address", "report", "address"),
    ("IP version", "analysis", "version"),
    ("Scope", "analysis", "scope"),
    ("Expanded form", "analysis", "expanded"),
    ("Reverse DNS name", "analysis", "reverse_dns_name"),
    ("ISP / Organization", "details", "isp"),
    ("ASN", "details", "asn"),
    ("Network", "details", "network"),
    ("City", "details", "city"),
    ("Region", "details", "region"),
    ("Country", "details", "country"),
    ("Country code", "details", "country_code"),
    ("Latitude", "details", "latitude"),
    ("Longitude", "details", "longitude"),
    ("Time zone", "details", "timezone"),
    ("Data source", "report", "source"),
)

# Hidden by --mask. ISP, ASN, and country stay visible as they are not specific
# to one customer.
MASKED_DETAILS = ("network", "city", "region", "latitude", "longitude")


def mask_address(address):
    """Keep only the leading part of an address, for demos and screenshots."""
    ip = ipaddress.ip_address(address)
    if ip.version == 4:
        return ".".join(str(ip).split(".")[:2] + ["xxx", "xxx"])
    return ":".join(ip.exploded.split(":")[:2] + ["xxxx"] * 6)


def address_bits(address, masked=False):
    """Return an address as binary groups: 8-bit octets or 16-bit hextets.

    When masked, "x" replaces each bit that mask_address() would hide, so the
    web page can't reveal a hidden address through its bit view.
    """
    ip = ipaddress.ip_address(address)
    width, group_size, visible = (32, 8, 16) if ip.version == 4 else (128, 16, 32)
    bits = format(int(ip), f"0{width}b")
    if masked:
        bits = bits[:visible] + "x" * (width - visible)
    return [bits[start : start + group_size] for start in range(0, width, group_size)]


def mask_comparison(comparison):
    """Return a copy of a provider comparison with identifying values hidden.

    Each row's status and the distance stay, since they don't reveal the location.
    """
    rows = []
    for row in comparison["rows"]:
        values = row["values"]
        if row["field"] in MASKED_DETAILS:
            values = {
                name: "(masked)" if value is not None else None
                for name, value in values.items()
            }
        rows.append({**row, "values": values})
    return {**comparison, "rows": rows}


def mask_report(report):
    """Return a copy of a report with identifying values hidden."""
    if not report.available:
        return report
    masked = mask_address(report.address)
    analysis = dict(report.analysis)
    analysis.update(compressed=masked, expanded=masked, reverse_dns_name="(masked)")
    details = {
        key: "(masked)" if key in MASKED_DETAILS and value is not None else value
        for key, value in report.details.items()
    }
    return replace(report, address=masked, analysis=analysis, details=details)


def _rows(report):
    sections = {
        "report": {"address": report.address, "source": report.source},
        "analysis": report.analysis,
        "details": report.details,
    }
    for label, section, key in ROWS:
        value = sections[section].get(key)
        if value not in (None, ""):
            yield label, str(value)


def render_table(report, color=True):
    """Return one report as a text table.

    Uses ASCII borders so it prints on any Windows console code page. Widths
    are calculated before color codes are added, as those have no visible width.
    """

    def paint(text, code):
        return f"{code}{text}{RESET}" if color else text

    lines = [paint(report.label, BOLD + CYAN)]
    if not report.available:
        lines.append(paint("  Not available", YELLOW))
    else:
        rows = list(_rows(report))
        left = max(len(label) for label, _ in rows)
        right = max(len(value) for _, value in rows)
        border = f"+-{'-' * left}-+-{'-' * right}-+"
        lines.append(border)
        for label, value in rows:
            shown = value.ljust(right)
            if label == "Address":
                shown = paint(shown, BOLD + GREEN)
            lines.append(f"| {label.ljust(left)} | {shown} |")
        lines.append(border)
    lines.extend(paint(f"  Note: {note}", YELLOW) for note in report.notes)
    return "\n".join(lines)


def render_json(reports):
    """Return all reports as JSON, for use by scripts."""
    return json.dumps([asdict(report) for report in reports], indent=2)


def render_report_file(reports, generated_at):
    """Return a saved report: the reports plus when and by which version they were made."""
    return json.dumps(
        {
            "generated_at": generated_at,
            "app_version": __version__,
            "reports": [asdict(report) for report in reports],
        },
        indent=2,
    )
