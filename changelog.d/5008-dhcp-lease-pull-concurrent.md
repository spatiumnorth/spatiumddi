### Fixed

- DHCP: the scheduled lease pull now reads agentless servers concurrently (bounded, with a per-server timeout) instead of one after another, so unreachable servers no longer hold a worker process for the sum of their connect bounds each interval. Results, audit rows and per-server error recording are unchanged (#5008)
