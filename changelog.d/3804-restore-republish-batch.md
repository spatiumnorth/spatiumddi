### Fixed

- A Trash restore's DDNS republish now works in batches of 20 addresses instead of 100, so its row locks are held for about 2 s rather than 10-15 s on a busy restored subnet (#3804).
