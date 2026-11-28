"""Web exposure detection (#3651): is this install reachable from outside the
operator's networks, and what has reached it.

Entirely local. No outbound connection, no external database, no reputation
feed (CLAUDE.md non-negotiable #17). The answer is a verdict WITH its
evidence, keyed on the spoofing-resistant client address
(``get_trusted_client_ip`` / ``TrustedProxyMiddleware``).

* :mod:`.classify` — ``trusted`` / ``internal`` / ``external`` and the bucket.
* :mod:`.config` — the module's configuration (``platform_settings.web_exposure``).
* :mod:`.store` — bounded Redis rolling counters.
* :mod:`.verdict` — the verdict + evidence.
* :mod:`.mitigations` — the opt-in responses (all default off).
"""
