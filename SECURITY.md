# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub: on this repository's **Security** tab, choose **Report a vulnerability**. Do not open a public issue.

Include what you found, how to reproduce it and what it affects. You should hear back within a week. Once a fix is released, the advisory is published with credit to you, unless you prefer otherwise.

## Supported versions

Only the latest release gets fixes. Update with `git pull && docker compose up -d --build`.

## What is in scope

- Leaks of webhook URLs or API keys (in logs, posts, alerts, state or the image)
- Feed content that can make the bot post something it should not, crash it, or exhaust its memory or disk
- Weaknesses in the Docker image or `compose.yaml` defaults

Out of scope: the security of the feeds themselves, and Discord's handling of posts.

## Handling secrets

Webhook URLs and API keys live only in `.env`, which is gitignored and kept out of the image. If one leaks, delete the webhook in Discord (**Edit Channel > Integrations > Webhooks**), create a new one, and update `.env`.
