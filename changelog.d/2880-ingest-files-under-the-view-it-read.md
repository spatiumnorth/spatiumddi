### Fixed

- **Under split-horizon, a learned record is filed only under the view it
  was read from.** The BIND9 agent's ingest read each dynamic zone with one
  loopback transfer, which BIND answers from whichever view first admits the
  loopback address, and the control plane filed the result under the copy of
  that name with the lowest view id. With a zone in two views and no shared
  copy, one view's records, managed and RFC 2136 alike, could be mirrored
  into the other view's zone and answered to that view's clients, and since
  #2666 on every server of the group. The agent now reads each view's copy
  with that view's own transfer key and names the view in its report; the
  control plane files a report under the zone row it reads from that view,
  and files a report that names no view (an older agent, PowerDNS) only when
  the group holds one row of that name. Anything else is not filed.

  Mirror rows filed in the wrong view before this change are not removed
  automatically: nothing recorded which view they were read from, so they
  cannot be told apart from correctly learned ones, and deleting a correct
  one removes a record a writer still owns. Once a wrongly filed row has been
  rendered into a view, that view's copy holds it and its reports keep it.
  To check a group with views, list the zone's records with the
  `ddns_external` source in each view and delete any that belong to another
  view; the deletion reaches the servers like any other record delete.
