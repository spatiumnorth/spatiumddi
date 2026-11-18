### Fixed

- The admin Change Requests Queue and History tabs page their lists ("Showing the newest 100 of 150" with a Load more button) instead of silently stopping at the newest 500 and 200 requests, and History now asks the API for decided requests only so pending ones no longer use up its window. `GET /api/v1/change-requests` gains `X-Total-Count` and takes a comma list for `state` (#4383).
