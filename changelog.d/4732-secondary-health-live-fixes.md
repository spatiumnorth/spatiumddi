### Fixed

- Per-secondary zone health now matches what BIND does when run live: zones with a short SOA refresh or retry no longer read as failing, a zone whose SOA expire is shorter than the alert window is no longer permanently expiring, a refresh that lands after the agent's last report no longer opens a short-lived transfer alert, and a copy BIND has dropped on expiry stays reported as expired instead of ageing out of the alert. (#4732)
