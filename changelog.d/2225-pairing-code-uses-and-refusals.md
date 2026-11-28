### Fixed

- **Fleet pairing codes now say how many appliances they admit, who used
  them, and why a joiner was refused (#2225).** The new-code dialog asks
  "how many appliances will join" (1 = single-use, N, or unlimited)
  instead of a persistent toggle, each code row lists the appliances
  that used it, and a Refused join attempts panel shows the node, the
  reason (used, full, expired, revoked, paused, unknown code) and a
  one-click new code, so a single-use code no longer fails the second
  joiner silently. The refused appliance's console now names the fix
  (new code, then F8 Re-pair); the wire answer stays one generic 403.

### Migrations

- `f4c1a7d92e68` — #2225, adds the `pairing_attempt` table.
