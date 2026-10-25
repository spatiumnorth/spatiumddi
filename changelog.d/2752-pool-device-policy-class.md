### Fixed

- **Add Pool can restrict a pool to a device policy's class (#2752).**
  The Device Policies tab shows the Kea class each policy generates and says
  a pool's class restriction binds to it, and the API accepts it, but the
  pool dialog's "Restrict to Client Class" list held only "No restriction"
  and the group's own client classes. It now also lists each of the group's
  device-policy classes, labelled with the policy's name (and "disabled"
  when it is, since a disabled policy's class is not rendered to Kea).
