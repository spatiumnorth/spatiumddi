### Fixed

- **The Copilot's "create DNS record" no longer writes into a zone an
  integration owns (#2653).** The REST create refuses a Tailscale- or
  NetBird-synthesised zone because the reconciler overwrites manual rows on
  the next sync; the copilot preview and apply did not, and apply never
  re-checked that the zone had not been trashed since the proposal. Both
  now refuse, through a helper shared with the REST handler.
