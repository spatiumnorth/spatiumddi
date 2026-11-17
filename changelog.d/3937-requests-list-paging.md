### Fixed

- The Requests page pages its list ("Showing the newest 100 of 101" with a Load more button) instead of silently showing only the newest 100 requests, so the oldest pending ones can be reached before they expire. `GET /api/v1/requests` gains `X-Total-Count`, and the `find_provisioning_requests` Copilot tool gains `offset` and `total` (#3937).
