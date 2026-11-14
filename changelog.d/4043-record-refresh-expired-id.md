### Fixed
- A DNS record create or update that raced its zone's permanent delete could still answer 500 instead of `404 Zone not found`: the 404 fallback read the expired record's id after the failed refresh. It now uses the instance identity (#4043).
