# Contributing

Bug reports, new sources and fixes are welcome.

## Before you start

- **A bug:** open an issue with what you ran, what happened and the log lines around it. Remove webhook URLs and API keys first: the bot never logs them, but your shell history or `.env` might.
- **A new source:** it must be a free, public feed. Follow [docs/adding-sources.md](docs/adding-sources.md), then open a pull request with the `check_feeds.py` output for it.
- **A larger change:** open an issue first, so we can agree on the approach before you write it.

## Making a change

1. Set up Python as in [docs/how-it-works.md](docs/how-it-works.md#run-without-docker) and install the dev extra: `pip install -e '.[dev]'`.
2. Make the change on a branch, with tests for new behaviour.
3. Run `pytest` (it runs offline) and, if you touched the image, `docker build .`.
4. Open a pull request saying what changed and why. CI runs the tests on Python 3.12 and 3.13 and builds the image.

Keep in mind:

- Never log, print or post a webhook URL or API key. Name the variable instead (`WEBHOOK_NEWS`). Tests check this for the existing paths.
- A new runtime dependency goes in `pyproject.toml` and both lock files (commands in [docs/how-it-works.md](docs/how-it-works.md#dependencies)).
- Keep the README short; detail belongs in `docs/`.

By contributing, you agree that your work is released under the [MIT License](LICENSE).
