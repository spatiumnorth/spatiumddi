### Fixed

- IPAM Merge preview names the values the sources disagree on as plain text (ISO dates, compact JSON for custom fields and tags, "none" for no value) instead of Python syntax such as `datetime.date(2031, 6, 30)` and `{'k': 'v'}` (#4831).
