### Fixed

- **Delete User and Delete Group said nothing when the server refused the
  delete (#2436).** Neither dialog read its mutation's failure, so a 404, the
  400 for deleting your own account or the 409 for removing the last
  superadmin left the dialog open and unchanged. A refusal is now shown in
  the dialog; a 404 (already deleted elsewhere) closes it and refreshes the
  list.
