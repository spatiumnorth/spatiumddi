### Fixed

- **Deleting a DNS view no longer serves its zones and records in
  every other view, and one zone name can no longer render twice in a
  view (#2275).** `view_id` on zones and records is `ON DELETE SET
  NULL`, and NULL means shared, so deleting `internal` answered its
  internal-only zones on `external`; a zone with a same-name twin in
  another view was then declared twice there, and BIND refused the
  whole group's config. Deleting a view that still scopes zones or
  records (Trash included) is now refused (409, naming them): move or
  delete them first. Blocking lists scoped to the view need
  `acknowledge_blocklist_detach=true` (the UI's confirm sends it after
  listing them), since the view's clients stop being filtered by them.
  The same twin can be reached without a delete, because a shared zone
  renders into every view and the `(group, view, name)` constraint
  cannot see that: zone create, update, restore, move and import,
  record changes that move a zone's views, and the copilot's zone
  create now refuse a change that would render one name twice in a
  view. An existing collision does not block unrelated edits.
