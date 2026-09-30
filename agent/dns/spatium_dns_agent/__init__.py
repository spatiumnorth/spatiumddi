"""SpatiumDDI DNS agent — supervises BIND9 and syncs with the control plane."""

import os

# The release this image was built from, stamped by the build
# (``APP_VERSION`` → ``SPATIUM_AGENT_VERSION``, see the image's Dockerfile).
# ``dev`` is an unstamped build. This was a literal date string that
# nothing rewrote, so every agent reported the day its package was first
# written, whatever release it shipped in (#1182; the supervisor's same
# defect was #1183).
# Capped at 64: the control plane's register and heartbeat bodies take at
# most that (and store it in a String(64)), so a longer stamp would 422
# every call and the agent could never register.
__version__ = os.environ.get("SPATIUM_AGENT_VERSION", "").strip()[:64] or "dev"
