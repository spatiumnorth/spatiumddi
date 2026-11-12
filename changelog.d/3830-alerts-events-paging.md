### Fixed
- The Alerts page no longer lists only the newest 100 events under "100 shown": it says "N of TOTAL shown" and a "Load more" button pages to the rest. `GET /api/v1/alerts/events` gains an `offset` parameter and an `X-Total-Count` header (still a bare list). (#3830)
