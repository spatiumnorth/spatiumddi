### Fixed

- The New request pickers now say "more match, keep typing to narrow" when more readable rows match than the 20 they show: `truncated` on `GET /api/v1/requests/resource-options` is true whenever a further readable match exists, not only when the permission scan cap was hit (#3938).
