### Fixed

- **A subnet's address rows no longer offer Edit and Delete to a
  read-only user (#2520).** The row's Edit, Delete, and an orphan row's
  Restore and Purge icons were shown for every address, so a Viewer
  opened Edit and was refused on Save. They now follow the same
  per-address write check that already grays the row and drops its
  checkbox.
