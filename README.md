# cyber-intel-discord-feeds

Security news, exploited vulnerabilities, vendor advisories and ransomware victims, posted to your Discord server every 15 minutes. Self-hosted in one Docker container.

## What you get

- **21 sources**, such as CISA, NVD, Microsoft, Cisco, BleepingComputer, Talos and ransomware.live, each posted to its own channel: news, vulnerabilities, advisories, research or ransomware victims.
- **Only the CVEs that matter:** every [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) addition (with an `@everyone` ping), CVEs scoring CVSS 9.8 or higher, and CVEs of products on your watchlist from 7.0. Each shows its CVSS and [EPSS](https://www.first.org/epss/) scores.
- **No repeats, no floods:** nothing posts twice, and no channel gets more than 10 posts a run.
- **Little to run:** no bot account, no database, no open ports. Alerts go to an ops channel if a source or a run keeps failing.

## Set it up

You need a Discord server you manage and a machine with [Docker](https://docs.docker.com/engine/install/) and Docker Compose. It takes about 10 minutes.

1. **Make the webhooks.** Create channels for news, vulnerabilities, advisories, research and ransomware, plus an optional ops channel for alerts. In each: **Edit Channel > Integrations > Webhooks > New Webhook > Copy Webhook URL**.
2. **Get the code:** `git clone <this repository's URL> && cd cyber-intel-discord-feeds`
3. **Add your webhooks:** `cp .env.example .env`, then paste each URL into `.env`.
4. **Check the setup:** `docker compose run --rm intel-feeds --test-post` sends one sample post to each channel.
5. **Start it:** `docker compose up -d`

The first run posts only each source's 3 newest items. The ransomware source is off until you add a [ransomware.live](https://www.ransomware.live) API key to `.env` and set `enabled: true` on it in `sources.yaml`.

The full guide: [docs/deploy-docker.md](docs/deploy-docker.md).

## Day to day

| To | Run |
| --- | --- |
| Watch the logs | `docker compose logs -f` |
| See if it is healthy | `docker compose ps` |
| Pause or resume | `docker compose stop` (`start` to resume) |
| Update | `git pull && docker compose up -d --build` |
| Back up the state | [Back up and restore](docs/deploy-docker.md#back-up-and-restore) |

## Customize

Sources, the watchlist, the CVSS bar and post limits are in `sources.yaml`. Edits apply on the next run, with no rebuild. To add a feed, see [docs/adding-sources.md](docs/adding-sources.md). Every environment variable is listed in [docs/configuration.md](docs/configuration.md).

## Docs

- [deploy-docker.md](docs/deploy-docker.md): setup, updates, logs, backups, moving servers, alerts
- [configuration.md](docs/configuration.md): every environment variable and setting
- [adding-sources.md](docs/adding-sources.md): adding a feed
- [how-it-works.md](docs/how-it-works.md): what each run does, running it without Docker, tests

## Contributing and security

Pull requests are welcome: see [CONTRIBUTING.md](CONTRIBUTING.md). To report a vulnerability, see [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE)
