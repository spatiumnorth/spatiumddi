### Changed

- **The control-plane appliance's self-registration answers only its own
  supervisor.** `POST /api/v1/appliance/self-register-bootstrap` mints the
  auto-approving pairing code the control-plane node's supervisor uses to
  register itself on first boot. It now requires a one-time token that the
  supervisor writes to the host release-state directory
  (`/var/lib/spatiumddi/release-state/self-bootstrap.token`, readable only
  by the supervisor and api pods) just before the call and removes straight
  after. Matching the host's install role is no longer treated as proof of
  who is calling, since the role is one of three fixed values and the route
  is reachable through the web UI's `/api/` proxy. The token is checked
  before anything else, so a call without it no longer clears
  never-heartbeated appliance rows or switches supervisor registration on.
  A supervisor older than the api sends no token and is refused; this only
  matters for a node that has never registered, or whose Fleet row was
  deleted, and both halves ship in the same appliance release.
