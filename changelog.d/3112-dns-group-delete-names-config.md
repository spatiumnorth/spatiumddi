### Fixed

- **Delete Server Group on a DNS group now names the views, ACLs and TSIG
  keys it destroys (#3112).** The dialog named only the group's zones in
  Trash, while the delete also removes the group's views, ACLs, TSIG keys,
  server options and its zones' pools, none of which reach Trash. The
  dialog now counts the views, ACLs and TSIG keys the group holds, the way
  the DHCP group's dialog does.
