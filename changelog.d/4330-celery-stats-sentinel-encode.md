### Fixed

- `celery inspect stats` answers again on appliances and other Sentinel-backed installs: the worker's reply no longer carries the broker's `sentinel_kwargs` (a non-JSON `Retry` object and the Sentinel password), which made every stats reply fail to encode (#4330).
