"""Fetch cybersecurity feeds and post new items to Discord webhooks."""

# The one place the version is set: pyproject.toml reads it from here
# (hatchling), so the Docker image, which runs from the source tree without
# installing the package, reports the same version.
__version__ = "1.0.0"
