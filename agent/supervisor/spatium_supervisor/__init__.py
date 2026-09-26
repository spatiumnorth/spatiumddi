"""Spatium appliance supervisor.

Phase A1 — scaffolding only. The supervisor owns every host-side
concern on an Application-role appliance: identity (Ed25519 keypair +
control-plane-signed cert), docker compose orchestration of service
containers, nftables drop-in management, and slot / system telemetry
reporting. None of that is implemented yet; this module currently
boots, logs its idle state, and sleeps.

See https://github.com/spatiumnorth/spatiumddi/issues/170 for the full
design.
"""

import os

# The release this image was built from, stamped by the build
# (``APP_VERSION`` → ``SPATIUM_SUPERVISOR_VERSION``, see the Dockerfile).
# ``dev`` is an unstamped build, which every version gate reads as unknown.
# This was a literal ``2026.05.14.1`` until #1183, which nothing rewrote,
# so every supervisor reported it and both #386 gates misfired.
__version__ = os.environ.get("SPATIUM_SUPERVISOR_VERSION", "").strip() or "dev"
