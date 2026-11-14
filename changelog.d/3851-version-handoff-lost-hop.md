### Fixed

- A rolling upgrade whose version hand-off hop was lost with a killed worker (OOM, node loss, the end of its shutdown grace) is now re-driven in a few minutes instead of after about 16, because each hop refreshes a short-lived Redis heartbeat that the orphan sweep reads, and a restarted celery beat now runs the sweep as it starts instead of waiting out its first interval (the shared-tag flip recreates beat mid hand-off). The fix protects upgrades started from a build that has it; a hand-off from an older build keeps the 15-minute grace (#3851).
