### Fixed

- The Celery worker consumer no longer opens a second broker connection per start or reconnect: the Sentinel-safe connection step now replaces the stock one instead of running beside it. (#4436)
