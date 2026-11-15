### Fixed
- A user whose role grants admin on one address set can now edit that set's name, description and tags; the address-sets router gate refused a set-scoped grant before the handler's own per-set check ran (#4007).
