### Fixed

- **A record a client adds by dynamic update stays in the view it was added
  through, and a zone pinned to a view renders into that view only (#3638).**
  Under split-horizon each view loads its own copy of a dynamic zone. When the
  agent reported a record a client had added to one view's copy, the control
  plane stored it with no view, so the next render put it into every view's
  copy and the other views' clients were answered it too. A record learned
  from a report that names its view is now stored scoped to that view when
  the zone renders into more than one view, and a report from one view no
  longer matches or removes a record learned in another. Learned records
  never change which views the zone itself renders into. Separately, a zone
  pinned to a view was still rendered, whole, into any other view one of its
  records named (a record left by a re-pin or restored from the Trash); it now
  renders into its pin alone, and that record is not served. Learned records
  stored before this release keep no view, and an agent older than the view
  field in its report stores them without one as before.
