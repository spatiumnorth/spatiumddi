### Fixed

  - **DHCP "Delete DHCP Server" no longer says scopes become unassigned 
  (#2609).** Scopes belong to the server group and stay with it. The dialog now 
  says so, and that if this was the group's last server nothing serves the 
  scopes until another server joins.
