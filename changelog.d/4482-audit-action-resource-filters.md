### Fixed

- The Audit Log page's Action and Resource filters now list every action and resource type the log holds (new `GET /api/v1/audit/facets`, same permission as the list), instead of fixed lists of six and thirteen values that could not reach appliance events, settings changes, API token events and most namespaced actions.
