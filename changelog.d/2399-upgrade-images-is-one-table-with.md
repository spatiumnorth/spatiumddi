### Fixed

- **Upgrade images is one table, with bulk management and an in-use
  refusal on delete (#2410).** The release `<select>` and the staged
  list are replaced by a single table, one row per version and
  architecture: channel, release date, size, staged, the fleet verdict
  and an "installed on / scheduled for / rolling run" column, grouped by
  release and sortable, with filters (fleet architecture, nightlies
  hidden with a count, staged, text) and a checkbox bulk toolbar for
  Delete and Import. The air-gap upload moved behind an "Upload
  image..." button in the shared modal. Server side, `GET
  /upgrade-images` gains `release`, `channel`, `fleet_architecture`,
  `installed_on`, `scheduled_for` and `rolling_run_id`; `GET
  /upgrade-images/available` gains `staged_image_id` and `channel`, an
  `all_architectures` flag, and a window that keeps looking until it has
  25 non-nightly releases (it used to be the newest 25, which a few
  weeks of nightlies could fill with no stable release at all). `DELETE`
  now answers 409 for an image an appliance is scheduled to fetch or an
  active run names, instead of leaving the node to 404 on its next
  fetch; `?force=true` overrides and is audited; only approved
  appliances count as scheduled. An air-gap image with no recorded
  architecture is linked to a release row only when that release
  publishes a single architecture, and otherwise shows as its own
  "unknown" row instead of marking every architecture of its tag as
  staged. Every staged image is its own row and selection (two images of
  one version and architecture no longer collide), a filter that hides a
  selected row unselects it, and the bulk Import leaves out rows no node
  can boot, like the per-row button. Both MCP tools carry the new fields
  and share one implementation with the REST endpoints
  (`services/appliance/upgrade_image_catalog.py`). No migration.

- **Upgrade images: only the fleet's architecture is offered, and a
  mismatched import or upload is refused (#2399).** The release picker
  listed every architecture and the import downloaded whichever row
  was picked, so a 1.5 GiB image no node could boot was stored before
  the #1026 scheduling gate ever ran. `GET /upgrade-images/available`
  now returns only images matching an approved appliance's reported
  architecture (with per-architecture node counts), and both the
  GitHub import and the air-gap upload answer 422 naming the fleet's
  architectures. The import refuses before downloading anything; the
  upload refuses before hashing or storing the image, but only after the
  request body has arrived (FastAPI receives a multipart upload before
  the handler runs), so the upload dialog offers only the fleet's
  architectures (plus "unknown") and an operator never sends the bytes
  for one the server would refuse. An appliance that has not reported an
  architecture lifts the restriction, and the UI says so. The duplicated
  description paragraph on the card is gone; the release picker itself
  became the #2410 table, where "This fleet's architecture" is the
  default filter.
