### Fixed

- On a multi-node appliance control plane, the plain-http traffic from the frontend nginx and from member supervisors to the api no longer crosses the node LAN: a second api Service with `internalTrafficPolicy: Local` (appliance only) keeps it on the caller's own node, and a supervisor with no ready local api pod falls back to its pinned https control-plane URL instead of cross-node http. Role agents, worker and beat are tracked separately (#4019) (#3645).
