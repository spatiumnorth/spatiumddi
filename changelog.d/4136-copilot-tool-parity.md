### Fixed

- The Operator Copilot's zone, MAC allowlist and MAC block operations now apply the same name and MAC validation as the REST API; a zone name that is not a valid domain name is refused wherever a zone is created, and the BIND9 agent declines to render one. `list_alerts`, `list_alert_rules` and `list_request_kinds` now require the same permission as their REST routes.
