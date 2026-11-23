### Fixed

- An install with no internet no longer reads as faulty: the appliance self-test asks the configured resolver about the host's own name instead of resolving `registry-1.docker.io`, the daily release check shows a neutral grey "GitHub unreachable" (amber stays for real HTTP errors), and Rolling Upgrade → Releases says GitHub isn't reachable instead of blaming rate limiting, logging the failed fetch once a minute rather than on every page view (#4799).
