### Fixed

- **Admin, Maintenance, Reboot no longer reboots whichever control-plane
  node the load balancer picks (#3011).** `POST /appliance/system/reboot`
  writes its trigger on the node that answers, and on a multi-node control
  plane the operator cannot choose that node. It is now refused with a 409,
  as `slot apply` already was, by the same shared check, and the message
  points to Fleet's per-appliance reboot. `GET /appliance/system/info` gains
  `reboot_available` and `reboot_unavailable_reason`, and the Maintenance tab
  shows a link to Fleet instead of the button. Single-node and compose
  installs are unchanged.
  On a multi-node control plane this also means a user with the Appliance
  Operator role (`admin` on `appliance`, not superadmin) can no longer reboot
  a node at all: Fleet's per-appliance reboot needs a superadmin (#2620).
