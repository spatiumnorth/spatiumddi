### Fixed

- **Record API refuses a view_id from another server group (#2501).**
  Create, update and bulk create accepted any view id; a foreign one made
  every operator view of the group skip the zone, so it silently stopped
  being served. They now 422 a view that is not one of the zone's own
  group (the check the zone-file import already ran, now shared), and a
  view other than the one the zone is pinned to.
