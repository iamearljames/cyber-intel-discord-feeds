# syntax=docker/dockerfile:1
# The bot as a long-running container. Python is pinned here: the
# minor version in the tag, the exact build by digest. Dependabot opens a
# PR when the base image gets a new build (security fixes); bump the tag
# by hand for a new Python minor version.
FROM python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Exact versions with hashes. The package itself is not pip-installed (that
# would fetch an unpinned build backend); it runs from /app/src instead.
COPY requirements.lock ./
RUN pip install --require-hashes --only-binary=:all: -r requirements.lock

COPY src/ ./src/
COPY sources.yaml ./
ENV PYTHONPATH=/app/src

# A non-root user owning /data, where the state file, its lock and the run
# status live. A named volume mounted there takes this ownership.
RUN useradd --system --uid 10001 --home-dir /data --shell /usr/sbin/nologin intel \
    && mkdir /data && chown intel:intel /data
USER intel
VOLUME /data

ENV INTEL_FEEDS_STATE=/data/state.json \
    INTEL_FEEDS_INTERVAL=15m

# Unhealthy when no run has worked for two intervals plus 5 minutes.
HEALTHCHECK --interval=5m --timeout=10s --start-period=10m --retries=1 \
    CMD ["python", "-m", "intel_feeds", "--health"]

# Runs every INTEL_FEEDS_INTERVAL with /app/sources.yaml (mount your own over
# it). Extra arguments go to the bot, for example --check-config or --test-post.
ENTRYPOINT ["python", "-m", "intel_feeds"]
