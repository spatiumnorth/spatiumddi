### Fixed

- DNS views: Sub-zone, and the zone tree's "Create zone … here", now open Add Zone on the parent zone's view instead of "No view". Before, a child zone saved with the dialog's defaults was stored with no view, and a zone with no view is served in every view of the group. The tree uses the nearest zone above the folder, and opens on "No view" when that name exists in more than one view. The "No view" option and the field's hint now say that it serves the zone in every view. (#4842)
