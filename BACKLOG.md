# Product Backlog

Enhancements for future revisions. Priority and effort are estimates for the team to review.

## Done in Project Activity 4

| # | Enhancement | Where |
| --- | --- | --- |
| 1 | Automated tests on every pull request (CircleCI) | `.circleci/config.yml` |
| 2 | Scheduled live check of each API | `.circleci/config.yml`, `tests/test_live.py` |
| 4 | Save a report to a file (`--output report.json`) | `__main__.py`, `display.py` |

## Still to do

| # | Enhancement | Value to technicians | Priority | Effort |
| --- | --- | --- | --- | --- |
| 3 | Show the computer's local IP addresses, gateway, and DNS servers | Puts local and public addressing in one view | High | Medium |
| 5 | Look up addresses from a file (`--file ips.txt`) | Handles many addresses from a log | Medium | Small |
| 6 | CSV output | Opens results in a spreadsheet | Medium | Small |
| 7 | Reverse DNS query (actual hostname for an address) | Identifies the host, not only the lookup name | Medium | Small |
| 8 | Optional paid API key through an environment variable | Allows higher rate limits for heavier use | Medium | Small |
| 9 | Short-lived result cache | Reduces API use during repeated checks | Low | Medium |
| 10 | Watch mode that reports address changes | Helps troubleshoot dynamic or changing addresses | Low | Medium |
| 11 | Installable command (`ipinfo`) | Removes the need to run from the project folder | Low | Small |
| 12 | Shared, hosted version of the web dashboard with sign-in | Lets a whole team use it from a browser, without installing it | Low | Large |
