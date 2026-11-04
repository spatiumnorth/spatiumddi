### Fixed

- **The Copilot's maintenance-mode tool can be switched on (#3415).**
  It shipped off for the operator to opt in, but it wrote directly,
  and the Tool Catalog's save drops every tool that does: its toggle
  snapped back off with no message. It is now
  `propose_set_maintenance_mode`. The Copilot stages the change as a
  proposal, and maintenance mode flips only when you click Apply, like
  every other Copilot write. It still ships off, superadmin only, and
  its toggle now holds. A Tool Catalog save that asks to enable a name
  it cannot keep now answers 422 naming it, instead of dropping it
  with a 200.
