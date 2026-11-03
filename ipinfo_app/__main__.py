"""Command-line entry point: python -m ipinfo_app

Exit codes: 0 = at least one address found, 1 = none found, 2 = bad arguments.
"""

import argparse
import ipaddress
import os
import sys

from . import __version__
from .api import DEFAULT_TIMEOUT, build_report, detect_report
from .display import mask_report, render_json, render_table


def _ip_argument(value):
    """Reject invalid --lookup values before any request is made."""
    try:
        return str(ipaddress.ip_address(value))
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"not a valid IP address: {value}") from exc


def _positive_number(value):
    try:
        number = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"not a number: {value}") from exc
    if number <= 0:
        raise argparse.ArgumentTypeError("must be greater than 0")
    return number


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        prog="python -m ipinfo_app",
        description="Show public IPv4/IPv6 addressing information.",
    )
    family = parser.add_mutually_exclusive_group()
    family.add_argument("-4", "--ipv4-only", action="store_true", help="only detect IPv4")
    family.add_argument("-6", "--ipv6-only", action="store_true", help="only detect IPv6")
    parser.add_argument(
        "-l",
        "--lookup",
        action="append",
        type=_ip_argument,
        metavar="IP",
        help="look up this address instead of detecting your own (repeatable)",
    )
    parser.add_argument("--json", action="store_true", help="print JSON instead of tables")
    parser.add_argument("--mask", action="store_true", help="hide identifying values, for demos")
    parser.add_argument("--no-color", action="store_true", help="disable colored output")
    parser.add_argument(
        "--timeout",
        type=_positive_number,
        default=DEFAULT_TIMEOUT,
        metavar="SECONDS",
        help=f"timeout per request (default: {DEFAULT_TIMEOUT})",
    )
    parser.add_argument("--version", action="version", version=__version__)
    args = parser.parse_args(argv)
    if args.lookup and (args.ipv4_only or args.ipv6_only):
        parser.error("-4 and -6 cannot be combined with --lookup")
    return args


def collect_reports(args):
    if args.lookup:
        return [
            build_report(f"Lookup: IPv{ipaddress.ip_address(ip).version}", ip, timeout=args.timeout)
            for ip in args.lookup
        ]
    versions = [4] if args.ipv4_only else [6] if args.ipv6_only else [4, 6]
    return [detect_report(version, timeout=args.timeout) for version in versions]


def use_color(args):
    """Use color only on a real terminal, and honor the NO_COLOR convention."""
    return not args.no_color and "NO_COLOR" not in os.environ and sys.stdout.isatty()


def main(argv=None):
    args = parse_args(argv)
    reports = collect_reports(args)
    if args.mask:
        reports = [mask_report(report) for report in reports]

    if args.json:
        print(render_json(reports))
    else:
        color = use_color(args)
        if color and os.name == "nt":
            os.system("")  # turns on ANSI color handling in the Windows console
        print("\n\n".join(render_table(report, color) for report in reports))

    return 0 if any(report.available for report in reports) else 1


if __name__ == "__main__":
    sys.exit(main())
