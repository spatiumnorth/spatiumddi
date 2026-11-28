### Fixed

- The alert rule editor's Delivery channels text no longer says an alert fans out to every enabled forwarding target (a target's own minimum severity and resource type filters can drop it), and the InfluxDB Export header no longer says every enabled target receives the DNS and DHCP counter deltas (each target selects its own metrics). (#4779)
