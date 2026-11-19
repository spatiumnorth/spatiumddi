### Fixed

- The Host timezone now stores the canonical name for a legacy alias (`US/Pacific` becomes `America/Los_Angeles`, `Asia/Calcutta` becomes `Asia/Kolkata`), because the appliance host has no legacy zone names and refused them forever. The field no longer suggests those names, and Fleet shows the host's reason when the timezone apply fails.
