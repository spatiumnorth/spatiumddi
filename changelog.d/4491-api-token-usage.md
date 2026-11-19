### Added

- API tokens now record how often they are used: calls per day (kept 90 days) and the address of the last call, shown on the API Tokens page with an "Idle only" filter, in `GET /api/v1/api-tokens` (`calls_30d`, `last_client_ip`, `?idle_days=N`), a per-token `GET /api/v1/api-tokens/{id}/usage` series, and a new `find_api_tokens` Copilot tool. Calls are counted in Redis and written in batches every five minutes, so requests gain no database write.
