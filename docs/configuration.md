# Configuration

Two places hold the configuration:

- **`.env`**: secrets and deployment choices, as environment variables. Copy `.env.example` to `.env` and fill it in. Docker Compose passes it to the container; outside Docker the bot loads `.env` from the working folder itself. A variable already set in the environment wins over the file.
- **`sources.yaml`**: the sources, the CVE filter, the watchlist and the post limits. Each key is explained in the file. Edits apply on the next run.

## Environment variables

| Variable | Needed | What it is |
| --- | --- | --- |
| `WEBHOOK_NEWS` | For the news channel | Discord webhook URL for news (BleepingComputer, The Hacker News, The Record, SecurityWeek, Krebs on Security) |
| `WEBHOOK_VULNS` | For the vulnerabilities channel | Webhook for CISA KEV additions and critical or watchlisted NVD CVEs |
| `WEBHOOK_ADVISORIES` | For the advisories channel | Webhook for CISA advisories and vendor PSIRTs (Microsoft, Cisco, Fortinet, Palo Alto Networks) |
| `WEBHOOK_RESEARCH` | For the research channel | Webhook for research blogs (Talos, Unit 42, Google, Microsoft, The DFIR Report, Huntress, Check Point, Elastic) |
| `WEBHOOK_RANSOM` | For the ransomware channel | Webhook for ransomware leak-site victims |
| `WEBHOOK_OPS` | Optional, recommended | Webhook for alerts: a source down for 24 hours, runs failing, and their recoveries |
| `RANSOMWARE_LIVE_API` | For the ransomware source | ransomware.live PRO API key. The source ships with `enabled: false`; set it to `true` once the key is in `.env`. Turned on without a key, it fails every run. |
| `NVD_API_KEY` | Optional | Free [NVD API key](https://nvd.nist.gov/developers/request-an-api-key): a higher rate limit, so NVD lookups fail less often |
| `INTEL_FEEDS_CONTACT` | Optional | A URL or email that feed operators can reach you at, sent in the User-Agent as `intel-feeds/<version> (+<contact>)`. Some sites block clients without one. Up to 200 printable ASCII characters. |
| `INTEL_FEEDS_INTERVAL` | Set by Docker | Time between runs: `15m` (the default in `compose.yaml`), `30m`, `1h`, `1h30m`; from `1m` to `24h`. Unset outside Docker, the bot runs once and exits. |
| `INTEL_FEEDS_STATE` | Set by Docker | Path of the state file: `/data/state.json` in the image. Outside Docker the default is `state.json` in the working folder. |

A category whose webhook is not set does not post, and every run logs a warning naming the variable. Its new items wait in state and post once the webhook is added. Logs and alerts name the variable, never the URL.

Webhook URLs and API keys are secrets. Keep `.env` out of git (it is in `.gitignore`), readable only by you (`chmod 600 .env`), and out of issues, logs and chat.

## Settings in `sources.yaml`

The `settings:` section at the top. Every key is optional; a missing key uses the default.

| Key | Default | What it does |
| --- | --- | --- |
| `cvss_min` | `9.8` | NVD and MSRC CVEs post only at this CVSS score or higher. CISA KEV additions always post. |
| `cve_lookups_per_run` | `20` | NVD score lookups per run for sources with `cve_filter: true` (MSRC), 0 to 40; the rest wait for later runs. Without `NVD_API_KEY` a run makes at most 4. |
| `watchlist.products` | 31 products | Product names; an NVD CVE naming one posts from `watchlist.min_cvss`. Whole words, case ignored. Edit it to match what you run. |
| `watchlist.min_cvss` | `7.0` | The CVSS bar for watchlisted products. |
| `watchlist.group_min` | `3` | When a run lets through this many CVEs or more for one product (a vendor's batch), they post as one summary. |
| `posts_per_channel` | `10` | Posts per channel per run; the rest go out on later runs. |
| `channel_caps` | `ransomware: 25` | Per-channel caps that differ from `posts_per_channel`. |
| `new_source_posts` | `3` | How many of a new source's newest items post on its first run; the rest are recorded as seen. |
| `max_age_days` | `7` | Items older than this never post. |
| `keep_days` | `90` | Items no feed lists any more are dropped from state after this many days. Keep it at least 4 times `max_age_days`. |
| `webhooks` | `news: WEBHOOK_NEWS`, and so on | Which environment variable holds each channel's webhook. Write the variable's name, never the URL. |

Each source entry has a `name`, `url` (https only), `type` (`rss`, `nvd`, `kev` or `ransomware`) and `category` (`news`, `vulns`, `advisories`, `research` or `ransomware`), and optionally `enabled`, `revisions`, `cve_filter`, `site`, `icon` and `notes`. See [adding-sources.md](adding-sources.md).

Check the file after any change:

```bash
docker compose run --rm intel-feeds --check-config
```
