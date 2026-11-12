# IPv4/IPv6 Address Information App

A Python command-line tool and local web dashboard that give network technicians a computer's public IP addressing information. Built for DEVASC Project Activity 3, Option 2.

It detects the public IPv4 and IPv6 addresses separately, then shows the ISP, ASN, network prefix, approximate location, and time zone. It can also look up any other IP address.

## Features

| Feature | How to use it | Why it helps technicians |
| --- | --- | --- |
| IPv4 and IPv6 detection | `python -m ipinfo_app` | Shows whether each protocol reaches the internet |
| Single-protocol check | `-4` or `-6` | Tests one protocol, with a usable exit code |
| Look up other addresses | `-l 8.8.8.8` (repeatable) | Identifies an address found in a log or trace |
| ISP, ASN, prefix, location | Included in the results | Identifies who operates an address and where it is roughly registered or located |
| Address analysis | Included in the results | Shows scope, expanded form, and reverse DNS name, even offline |
| Provider fallback | Automatic | Keeps working when one free API is rate limited or down |
| JSON output | `--json` | Lets scripts and other tools use the results |
| Masked output | `--mask` | Hides identifying values in demos and screenshots |
| Readable tables | Default, or `--no-color` | Highlights the address, and removes color when output is redirected |

## Setup

Requires Python 3.10 or newer. No API keys are needed.

```bash
git clone https://github.com/bible420/devasc-ip-info.git
cd devasc-ip-info
python -m venv .venv
.venv\Scripts\activate          # Windows
# source .venv/bin/activate     # macOS or Linux
pip install -r requirements.txt
```

## Usage

```text
python -m ipinfo_app                       Detect your public IPv4 and IPv6
python -m ipinfo_app --mask                Same, safe to show on screen
python -m ipinfo_app -4                    IPv4 only
python -m ipinfo_app -6                    IPv6 only
python -m ipinfo_app -l 8.8.8.8 -l ::1     Look up specific addresses
python -m ipinfo_app -l 8.8.8.8 --json     JSON output
python -m ipinfo_app --help                All options
```

| Exit code | Meaning |
| --- | --- |
| 0 | At least one address was found |
| 1 | No address was found |
| 2 | Invalid arguments |

### Sample output

```text
Lookup: IPv4
+--------------------+----------------------+
| Address            | 8.8.8.8              |
| IP version         | 4                    |
| Scope              | global               |
| Expanded form      | 8.8.8.8              |
| Reverse DNS name   | 8.8.8.8.in-addr.arpa |
| ISP / Organization | Google LLC           |
| ASN                | AS15169              |
| Network            | 8.8.8.0/24           |
| City               | Mountain View        |
| Region             | California           |
| Country            | United States        |
| Country code       | US                   |
| Latitude           | 37.42301             |
| Longitude          | -122.083352          |
| Time zone          | America/Los_Angeles  |
| Data source        | ipapi.co             |
+--------------------+----------------------+
```

## Web dashboard

Address Bench is a web dashboard, styled like the front panel of a network device, that runs on your own computer.

```bash
python -m ipinfo_app.web
```

This opens `http://127.0.0.1:5000` in your browser. Press Ctrl+C in the terminal to stop it, or add `--port 8080` if port 5000 is in use.

| Panel | What it shows |
| --- | --- |
| Connection lights | Whether public IPv4 and IPv6 are working |
| Address anatomy | Every bit of the address as a light, split into network and host bits at the prefix boundary |
| Provider cross-check | Where the two APIs disagree about an address, and how far apart their locations are |
| Copy for ticket | The current results as plain text, ready to paste into a support ticket |

**Hide my address** is on by default for your own address. It doesn't apply to addresses you type into the lookup box.

## How it works

```text
__main__.py  Command-line tool: reads arguments, chooses addresses, sets the exit code
web.py       Web dashboard: serves the page in templates/ and static/, and the JSON routes
    |
api.py       Calls the REST APIs and builds an IPReport for each address
    |
display.py   Formats reports, applies masking, and builds the bit view
```

| API | Used for | Note |
| --- | --- | --- |
| `api.ipify.org` | Public IPv4 | Free, no key |
| `api6.ipify.org` | Public IPv6 | Only resolves when the network has IPv6 |
| `ipapi.co` | Address details, tried first | Free tier is rate limited |
| `ipwho.is` | Address details, fallback | Does not return the network prefix |

The code handles these cases on purpose:

- **No IPv6:** this is reported as "Not available", because many networks don't have it.
- **Details unavailable:** if every details provider fails, the address and its analysis still appear.
- **Private and other non-global addresses:** these are never sent to a provider, because no public record exists for them.
- **Invalid input:** every address is validated before it can be placed in a request URL.

## Limitations

- **Location is approximate.** During testing, the two providers placed 8.8.8.8 in different cities (Mountain View and San Jose). Do not use it to find a physical site.
- **Lookups are shared with third parties.** Detection and lookups send addresses to the APIs above, so check that this is acceptable before looking up sensitive addresses.
- **Masked output is not anonymous.** `--mask` hides the end of the address and the detailed location, but leaves the first part of the address, ISP, ASN, country, and time zone visible.
- **The cross-check uses more quota.** It calls every provider, so it only runs when you click the button.
- **Free APIs can change.** Rate limits and response formats are controlled by the providers.

## Testing

```bash
python -m unittest discover -v
```

### Continuous integration

[CircleCI](https://circleci.com) runs these tests automatically on every push, including pull request branches, using Python 3.10 and 3.12. The pipeline is in [`.circleci/config.yml`](.circleci/config.yml), and its results appear on each commit and pull request in GitHub.

- **Pull requests:** `main` is protected, so a pull request can only be merged after both test jobs pass and a teammate approves it.
- **Merges to `main`:** after the tests pass, a `package` job builds the app as `address-bench.zip`, which can be downloaded from the job's **Artifacts** tab in CircleCI.

The tests fake all HTTP traffic, so they run offline and use no API quota. They can't detect a provider changing its response format, so a separate set of live tests calls the real APIs.

### Live API check

[`tests/test_live.py`](tests/test_live.py) checks that each provider still returns the fields the app needs, using 8.8.8.8 as a known address. It runs as the `live-check` job in [`.circleci/config.yml`](.circleci/config.yml), whenever a pipeline is started with the `run-live-check` parameter set to `true`. A provider that is only rate limiting is skipped rather than failed.

To run it every day, add a schedule in CircleCI under **Project Settings > Triggers**: branch `main`, daily at 00:00 UTC, with the pipeline parameter `run-live-check` set to `true`. To run it once, use **Trigger Pipeline** on the project page with the same parameter.

To run it locally:

```bash
RUN_LIVE_TESTS=1 python -m unittest tests.test_live -v        # macOS or Linux
$env:RUN_LIVE_TESTS="1"; python -m unittest tests.test_live -v  # Windows PowerShell
```

Before a release, also try the app by hand:

```bash
python -m ipinfo_app --mask
python -m ipinfo_app -l 8.8.8.8 -l 2001:4860:4860::8888 -l 10.0.0.1
```

## Continuing this project

1. Choose an item from [BACKLOG.md](BACKLOG.md).
2. Update `main`, then create a branch such as `feature/save-report`.
3. Make the change and add tests. Most changes belong in one module:
   - **New API provider:** add a parser and a `PROVIDERS` entry in `api.py`. The parser must return every key in `DETAIL_FIELDS`.
   - **New table row:** add it to `ROWS` in `display.py`. If it could identify someone, add it to `mask_report` too.
   - **New option:** add it in `parse_args` in `__main__.py`.
   - **New dashboard feature:** add a route in `web.py` and its display code in `static/app.js`. Apply masking on the server, and write API data to the page as text, not HTML.
4. Run the tests and live checks above.
5. Open a pull request. CircleCI runs the tests automatically, and a teammate reviews it.
6. Merge once the tests pass and the review is approved. GitHub blocks the merge until both are done.

Don't commit API keys or unmasked output containing a real public IP. `.env` files are already ignored by git.
