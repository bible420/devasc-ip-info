# Product Backlog

Enhancements for a future revision, ready for Project Activity 4. Priority and effort are initial estimates for the team to review.

| # | Enhancement | Value to technicians | Priority | Effort |
| --- | --- | --- | --- | --- |
| 1 | Automated tests on every pull request (GitHub Actions) | Catches regressions before merge | High | Small |
| 2 | Scheduled live check of each API | Detects provider response changes that the offline tests can't | High | Small |
| 3 | Show the computer's local IP addresses, gateway, and DNS servers | Puts local and public addressing in one view | High | Medium |
| 4 | Save a report to a file (`--output report.json`) | Lets a report be attached to a support ticket | Medium | Small |
| 5 | Look up addresses from a file (`--file ips.txt`) | Handles many addresses from a log | Medium | Small |
| 6 | CSV output | Opens results in a spreadsheet | Medium | Small |
| 7 | Reverse DNS query (actual hostname for an address) | Identifies the host, not only the lookup name | Medium | Small |
| 8 | Optional paid API key through an environment variable | Allows higher rate limits for heavier use | Medium | Small |
| 9 | Short-lived result cache | Reduces API use during repeated checks | Low | Medium |
| 10 | Watch mode that reports address changes | Helps troubleshoot dynamic or changing addresses | Low | Medium |
| 11 | Installable command (`ipinfo`) | Removes the need to run from the project folder | Low | Small |
| 12 | Web dashboard | Helps technicians who prefer a browser over a terminal | Low | Large |
