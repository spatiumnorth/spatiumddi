### Fixed

- **A deleted customer, overlay or service now shows in Administration, Trash
  and no longer holds its name (#2738).** Deleting one only stamped it as
  deleted: it was in no Trash list, could not be restored or purged, and its
  name stayed taken, so creating it again answered "The request conflicts with
  existing data." All three are Trash types now (restore, permanent delete, and
  the retention sweep), and their name keys cover live rows only, so a deleted
  name can be used again. Migration `c8d3a1f47e92` swaps the three unique
  constraints for partial indexes; nothing is changed or removed on upgrade.
  A restore that would collide with a live row of the same name is refused
  (409) with the reason, and so is restoring a service or overlay whose customer
  is still in the Trash. Permanently deleting a customer is refused while it
  still has services. Rows deleted before this release appear in the Trash with
  their original delete time, so the ones older than the retention period are
  purged by the next nightly sweep. A name conflict on create now says which
  field is in use.
