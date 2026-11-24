# Adding a source

Every feed lives in [`sources.yaml`](../sources.yaml) at the repo root. Adding a source means adding one entry there; no code changes.

## 1. Find the feed URL

Use the feed itself, not the site's home page. Most blogs and news sites publish RSS or Atom:

- Look for an RSS icon or a "Feeds" or "Subscribe" page.
- Try the site address plus `/feed/` or `/rss/`.
- Open the URL in a browser. A feed starts with `<?xml` and contains `<rss` or `<feed`. An HTML page is not a feed.

Only free, public feeds. No paywalled or login-only sources.

## 2. Add the entry

Copy the template at the top of `sources.yaml` to the end of the `sources:` list. Remove the leading `# ` from each line and keep the two-space indent. Fill in four fields:

```yaml
  - name: Example Security Blog
    url: https://example.com/feed/
    type: rss
    category: research
```

| Field | Required | Allowed values |
| --- | --- | --- |
| `name` | yes | Any text, unique in the file. Shown on each post and in error messages. |
| `url` | yes | Full `https://` URL of the feed. |
| `type` | yes | `rss` for any RSS or Atom feed. `kev` and `nvd` are the two built-in vulnerability sources and `ransomware` the ransomware.live victims API (needs `RANSOMWARE_LIVE_API`); new sources use `rss`. |
| `category` | yes | `news`, `vulns`, `advisories`, `research` or `ransomware` (only with type `ransomware`). Picks the Discord channel. |
| `enabled` | no | `true` (default) or `false` to pause the source. |
| `revisions` | no | `false` (default) or `true`, `rss` only. Set `true` for a vendor feed that relists a revised advisory under the same GUID with a new date; each new date then posts again. Microsoft MSRC uses it. |
| `cve_filter` | no | `false` (default) or `true`, `rss` only. Set `true` for a vendor feed with one entry per CVE: only entries whose CVE is in the CISA KEV catalog or scores CVSS 9.8 or higher (`cvss_min` in the settings) post. Scores are looked up in NVD, one request per entry, so use it only where needed. Microsoft MSRC uses it. |
| `site` | no | The source's home page, `https://`. Each post shows the source name at the top, linking here. |
| `icon` | no | An `https://` image URL (PNG or JPEG; Discord may not show `.ico`) shown beside the source name. Try the site's `/apple-touch-icon.png`, or Google's favicon service: `https://www.google.com/s2/favicons?domain=example.com&sz=64`. |
| `notes` | no | Free text for humans: why it is here, quirks, volume. |

To pause a noisy or broken source, set `enabled: false` instead of deleting it.

## 3. Check it

First check the file itself. This reads `sources.yaml`, reports every problem at once, and fetches nothing:

```bash
docker compose run --rm intel-feeds --check-config   # in Docker
python -m intel_feeds --check-config                 # without Docker
```

A good file prints a line like `sources.yaml: OK, 21 sources (20 enabled)`. A bad one exits with a non-zero code and lists each problem with its line number and source name, for example:

```
Config check failed with 2 problems:
  sources.yaml:180: source "Example Security Blog": unknown category "new"; did you mean 'news'? (allowed: news, vulns, advisories, research, ransomware)
  sources.yaml:180: source "Example Security Blog": 'url' must start with https:// (found "http://example.com/feed/")
```

Warnings such as `no webhook for category "news": WEBHOOK_NEWS is not set` mean that variable is missing from both your shell and `.env`; they do not fail the check.

Then run the feed checker from the repo root (it needs the Python setup in [how-it-works.md](how-it-works.md#run-without-docker)). It fetches the source and prints the HTTP status, the format it found in the body, the item count, the newest item date, the size, and whether the server supports conditional requests (ETag, Last-Modified). It exits non-zero if the source returns no items:

```bash
python scripts/check_feeds.py --source "Example Security Blog"
python scripts/check_feeds.py            # every enabled source
```

Some sites answer a data centre's network differently from a home connection. On GitHub, the **Check feeds** workflow (`gh workflow run check-feeds.yml`) runs the same checker from GitHub's network.

Every run does the same config check first, so a mistake that slips through stops that run with the same messages (and a **Runs failing** alert to the ops channel) instead of posting.

## 4. Use it

In Docker, `sources.yaml` is mounted into the container, so the next run uses the new entry: no rebuild or restart.

A public feed others would want too is welcome as a pull request: see [CONTRIBUTING.md](../CONTRIBUTING.md).

## What happens on the first run

A new source does not flood its channel. On its first run only its newest 3 items post (`new_source_posts` in the settings), and the rest are recorded as seen. After that, each new item posts once.
