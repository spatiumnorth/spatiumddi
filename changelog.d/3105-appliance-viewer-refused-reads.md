### Fixed

- **A read-only Viewer on the Appliance page is no longer offered the
  MetalLB form, asked for refused reads again and again, or told there is
  nothing there (#3105, #3106, #3107).** Network & Host showed the
  "Control-plane VIP (MetalLB)" form to a Viewer over a settings read the
  server refuses, and the card now says changing it is restricted to
  superadmins instead. A read the server refused (403) on this page is no
  longer asked again on a timer, which also stops a denied audit row every
  ten seconds for as long as the tab stayed open. The Cluster etcd
  snapshots, the Firewall Logs appliance picker, the firewall policies and
  aliases, and the Pods list now say the read was refused rather than "No
  recoverable etcd snapshots yet", "No online appliances", "No policies
  yet" or "No pods visible".
