# Deploy with Docker

The bot runs as one long-running container. Every 15 minutes it fetches the feeds, posts what is new, and saves what it has seen to a state file on a Docker volume. It needs no inbound ports, database or bot account: it only makes outbound HTTPS requests to the feeds and to Discord.

- [Requirements](#requirements)
- [Set up](#set-up)
- [What runs](#what-runs)
- [Check that it works](#check-that-it-works)
- [Day to day](#day-to-day)
- [Update](#update)
- [Back up and restore](#back-up-and-restore)
- [Move to another server](#move-to-another-server)
- [Alerts](#alerts)
- [Troubleshooting](#troubleshooting)

## Requirements

- Docker Engine with the Compose plugin (`docker compose version` prints v2 or newer). Any Linux server, a home server, or Docker Desktop works; the image is about 190 MB.
- A Discord server where you can manage webhooks.
- Optional: a free [NVD API key](https://nvd.nist.gov/developers/request-an-api-key) (higher rate limit) and a [ransomware.live](https://www.ransomware.live) PRO API key for the ransomware channel.

## Set up

1. **Create the channels and webhooks.** One channel per category: news, vulnerabilities, advisories, research and ransomware. An ops channel for alerts is optional but recommended. In each channel: **Edit Channel > Integrations > Webhooks > New Webhook > Copy Webhook URL**. Two categories can share a channel: give them the same URL.

2. **Get the code:**

   ```bash
   git clone <this repository's URL>
   cd cyber-intel-discord-feeds
   ```

3. **Fill in `.env`:**

   ```bash
   cp .env.example .env
   chmod 600 .env
   ```

   Paste each webhook URL after its name, and any API keys. Every variable is described in [configuration.md](configuration.md). Anyone holding a webhook URL can post to that channel: never commit `.env` or paste the URLs anywhere.

4. **Choose the sources.** `sources.yaml` ships with 21 sources, 20 of them on. The `ransomware.live` entry is off: with a ransomware.live PRO key in `.env`, set `enabled: true` on it. Check the file:

   ```bash
   docker compose run --rm intel-feeds --check-config
   ```

   The first command builds the image, which takes about a minute.

5. **Send a test post:**

   ```bash
   docker compose run --rm intel-feeds --test-post
   ```

   Each channel whose webhook is set gets one sample post, labeled as a test. It exits 0 only if every post went through.

6. **Start it:**

   ```bash
   docker compose up -d
   ```

   The first run starts at once. To keep a new channel from being flooded, it posts only each source's 3 newest items and records the rest as seen. Later runs post each new item once.

## What runs

`compose.yaml` defines one service, `intel-feeds`:

| What | Where |
| --- | --- |
| Schedule | `INTEL_FEEDS_INTERVAL` (default `15m`): one run at start, then at :00, :15, :30 and :45 UTC |
| Sources and settings | `./sources.yaml`, mounted read-only at `/app/sources.yaml` and read again on every run |
| Webhooks and keys | `.env`, passed in as environment variables |
| State | The `data` volume at `/data`: `state.json` (what was seen and posted), `state.status.json` (the last run and any failure streak) and `state.json.lock` |
| User | Unprivileged user `intel` (uid 10001) |
| Restart | `unless-stopped`: it comes back after a crash or a reboot |
| Logs | Docker's `json-file` driver, rotated at 10 MB, 3 files kept |

Only one run happens at a time. A second container or a `docker compose run` that starts while a run is going skips its turn.

## Check that it works

```bash
docker compose ps        # STATUS shows (healthy) once a run has worked
docker compose logs -f   # each run ends with "run: finished in N s; ..."
```

A healthy log looks like this:

```
schedule: every 15m, starting now
fetch: 20 fetched, 1 not modified, 0 failed
post: 6 posted, 0 failed, 0 over the per-channel cap, 0 kept for a missing webhook
run: finished in 17.6 s; 50 new, 44 filtered, 6 posted, 0 left, 0 errors
schedule: next run at 2026-11-24 08:00:00 UTC
```

The container is marked unhealthy when no run has worked for two intervals plus 5 minutes (35 minutes at `15m`). To ask directly: `docker compose exec intel-feeds python -m intel_feeds --health`.

## Day to day

| To | Run |
| --- | --- |
| Follow the log | `docker compose logs -f` |
| Last day of runs | `docker compose logs --since 24h \| grep 'run: finished'` |
| Pause, resume | `docker compose stop`, `docker compose start` |
| Run once now | `docker compose restart` (a run starts at once) |
| Change the interval | Edit `INTEL_FEEDS_INTERVAL` in `compose.yaml` (for example `30m`), then `docker compose up -d` |
| Change sources or limits | Edit `sources.yaml`; the next run uses it. Check it first with `docker compose run --rm intel-feeds --check-config` |
| Stop and remove the container | `docker compose down` (the state volume stays) |

When the container stops, a run in progress gets up to 60 seconds to finish (`stop_grace_period`). A run cut short loses nothing: the state file is replaced in one step, and the next run picks up where the last saved one left off.

## Update

```bash
git pull
docker compose up -d --build
```

Compose rebuilds the image and replaces the container; the state volume is kept. If you edited `sources.yaml` and the update changes it too, `git pull` stops: run `git stash`, `git pull`, `git stash pop`, and fix any lines it marks.

## Back up and restore

The state file is the only data worth keeping: without it, a new start records everything as seen again (posting each source's 3 newest items) and the watch for repeats starts over. It is plain JSON, usually a few MB.

Back up, while it runs:

```bash
docker compose exec intel-feeds cat /data/state.json > state-backup.json
```

Restore:

```bash
docker compose stop
docker compose run --rm --no-deps -v "$PWD/state-backup.json:/restore.json:ro" \
  --entrypoint cp intel-feeds /restore.json /data/state.json
docker compose start
```

To start over on purpose, remove the volume: `docker compose down -v`, then `docker compose up -d`.

To keep state in a folder on the host instead of a named volume, replace `data:/data` in `compose.yaml` with `./data:/data`, and make the folder writable for uid 10001: `mkdir data && sudo chown 10001 data`.

## Move to another server

1. On the old server, back up the state (above), then stop it for good: `docker compose down`. Two servers running at once post everything twice.
2. On the new one, set up the code as in [Set up](#set-up) steps 2 and 3, and copy over `.env`, your `sources.yaml` and `state-backup.json`.
3. Restore the state (above), then `docker compose up -d`.

## Alerts

With `WEBHOOK_OPS` set, the ops channel gets:

| Alert | When |
| --- | --- |
| **Source down: \<name\>** | A source has failed every run for 24 hours. Includes the last error. |
| **Source back: \<name\>** | That source works again. |
| **Runs failing** | A whole run failed: `sources.yaml` is invalid, the state file cannot be read or written, a post could not be sent, or the run crashed. Sent once per streak. |
| **Runs working again** | The first run that works after a Runs failing alert. |

A single feed failing is normal (sites go down for a while) and does not count as a failed run. An alert that cannot be sent is tried again on the next run.

## Troubleshooting

| You see | Do this |
| --- | --- |
| `Config check failed with N problems` | Fix the lines it names in `sources.yaml`; the next run picks it up. |
| `no webhook for category "news": WEBHOOK_NEWS is not set` | Add the URL to `.env`, then `docker compose up -d` so the container gets it. |
| `env file .../.env not found` | Run `cp .env.example .env` and fill it in. |
| `State file problem: ... Permission denied` | With a host folder for `/data`, run `sudo chown 10001` on it. |
| `State file problem: ... not valid JSON` | Restore a backup, or remove the volume to start over. The run stops instead of starting from empty, which would mark everything as new. |
| `(unhealthy)` in `docker compose ps` | Read `docker compose logs --since 1h` for the failing step. |
| A source fails with HTTP 403 | Some sites block data-centre IP ranges. Try setting `INTEL_FEEDS_CONTACT` in `.env`, or turn the source off. |

Exit codes of a single run: 0 worked, 1 a post or alert could not be sent, 2 `sources.yaml` problem, 3 state file problem, 4 crash (the log has the traceback).
