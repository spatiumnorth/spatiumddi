### Fixed

- A rolling upgrade whose version hand-off hop was lost with a killed worker (OOM, node loss, the end of its shutdown grace) is now re-driven about two minutes later instead of after about 16, because each hop refreshes a short-lived Redis heartbeat that the orphan sweep reads. The fix protects upgrades started from a build that has it; a hand-off from an older build keeps the 15-minute grace (#3851).
