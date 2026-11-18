### Fixed

- A wake schedule in the default `UTC` zone could not be saved from the console in Chromium-based browsers, and the Host timezone field refused `UTC` too: both checked the name against the browser's list of zones, which has no `UTC`. They now ask the browser whether it can resolve the zone, so `UTC`, `Etc/UTC` and aliases like `US/Pacific` are accepted, while names the API would reject (misspellings, offsets such as `+01:00`, wrong-case names such as `utc`) are still refused. (#4409)
