### Fixed

- **DHCP "Delete Server Group" names what the delete destroys
  (#2607).** The dialog spoke only of scopes in Trash, while the
  delete also removes the group's MAC blocks, client classes, option
  templates, PXE profiles, device policies and phone profiles (and its
  responder and router-advertisement records), none of it into Trash.
  It now counts each kind it can read and names one it cannot.
