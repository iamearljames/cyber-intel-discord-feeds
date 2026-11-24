# Feed check results

All 16 enabled sources returned items on 2026-11-18 (`python scripts/check_feeds.py`, from a home connection). Rerun the script, or the **Check feeds** workflow in Actions, before relying on these numbers.

| Source | Format | Items | Size | ETag | Last-Modified |
| --- | --- | --- | --- | --- | --- |
| CISA KEV | JSON | 1,782 (whole catalog) | 1.9 MB | yes | yes |
| NVD CVE API | JSON | about 1,245 published per day | 15 kB for a 5-CVE page | no | no |
| CISA Cybersecurity Advisories | RSS 2.0 | 30 | 359 kB | no | no |
| Microsoft MSRC | RSS 2.0 | 5,782 (4,851 unique GUIDs) | 3.3 MB | yes | yes |
| Cisco PSIRT | RSS 2.0 | 50 | 145 kB | no | no |
| Fortinet PSIRT | RSS 2.0 | 50 | 48 kB | yes | yes |
| Palo Alto Networks Security Advisories | RSS 2.0 | 25 | 8 kB | yes | no |
| BleepingComputer | RSS 2.0 | 15 | 13 kB | yes | yes |
| The Hacker News | RSS 2.0 | 50 | 60 kB | no | yes |
| The Record | RSS 2.0 | 5 | 5 kB | no | no |
| SecurityWeek | RSS 2.0 | 10 | 12 kB | yes | yes |
| Krebs on Security | RSS 2.0 | 10 | 120 kB | no | yes |
| Cisco Talos | RSS 2.0 | 15 | 1.0 MB | yes | no |
| Unit 42 | RSS 2.0 | 15 | 24 kB | yes | yes |
| Google Threat Intelligence | RSS 2.0 | 20 | 1.6 MB | no | yes |
| Microsoft Security Blog | RSS 2.0 | 10 | 345 kB | yes | yes |

Every RSS entry had a parseable date, a GUID and a link. feedparser raised no warnings for any feed.

## Sources that need special handling

- **Microsoft MSRC** repeats each CVE once per revision under the same GUID, and the feed holds about 3 months of history. Dedup by GUID posts only the first revision. The first-run flood guard matters most here.
- **NVD** is queried by a publish-date window, not with conditional requests. At about 1,200 CVEs a day, the CVSS ≥ 9.8 filter and paging are required. It is rate limited without an `NVD_API_KEY`.
- **CISA Cybersecurity Advisories** returns 200 to httpx, the job's HTTP client, but 403 Access Denied to curl whatever the user agent (3 tries each on 2026-11-18). Check it with the checker, not curl. Its dates use two-digit years ("17 Nov 26"), which feedparser reads correctly.
- **Cisco PSIRT** dates have no timezone ("2026-11-17 23:53:12.0"). feedparser reads them as UTC. If Cisco means another timezone, Cisco's latency figures will be off by that offset.
- **Krebs on Security** sends valid RSS as `text/html`. Detect the format from the body, never the header.
- **No conditional requests**: 4 sources send neither ETag nor Last-Modified (CISA advisories, Cisco PSIRT, The Record, NVD). They are re-downloaded in full each run; the largest is the CISA advisories feed at 359 kB.
- **Conditional requests ignored**: The Hacker News and Google Threat Intelligence (both served by Feedburner) send Last-Modified but answer 200 to `If-Modified-Since`, so they are downloaded in full each run like the 4 above. On a second fetch on 2026-11-18, the other 10 sources with validators answered 304.
- **Large feeds**: MSRC (3.3 MB), KEV (1.9 MB), Google Threat Intelligence (1.6 MB) and Talos (1.0 MB). Use conditional requests where offered.

## Test fixtures

`python scripts/check_feeds.py --save-fixtures tests/fixtures` saved one response per source type and feed format, the smallest of each:

- `tests/fixtures/rss20_the_record.xml`: RSS 2.0, 5 items
- `tests/fixtures/kev.json`: the KEV catalog cut to its 5 newest entries
- `tests/fixtures/nvd.json`: one NVD API page of 5 CVEs

- `tests/fixtures/rss20_cisco_psirt.xml`: the Cisco PSIRT feed cut to its first 2 items, added by hand for its timezone-less dates and escaped HTML

`tests/test_items.py` parses each of them offline.
