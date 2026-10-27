### Fixed

- **Requests Kea evicts from its full packet queue are now counted
  (#2889).** In a burst deeper than kea-dhcp4's 1,024-packet
  multi-threading queue, Kea drops the oldest queued requests and keeps
  no statistic for it, so `socket_drop`, `receive_drop` and
  `pkt4-received` all stayed silent while clients waited out retransmit
  rounds. The DHCP agent now counts DHCPv4 arrivals at Kea's intake with
  a BPF-filtered `AF_PACKET` socket of its own (the `CAP_NET_RAW` it
  already holds, no new privilege) and reports `queue_evicted` =
  arrivals − DHCPv4 `socket_drop` − `pkt4-received` per bucket. It
  reports only an eviction the next sample confirms, so a backlog that
  is merely in flight at one read is never counted, and an eviction
  lands one bucket late. The Stats tab's DROPPED line and chip, the
  InfluxDB export, `find_dhcp_server_stats`'s `packet_loss` block and
  the default-on `dhcp_packets_dropped` alert include it. NULL means
  unmeasured: no raw socket, a DHCPv6-only server, or the bucket after a
  Kea restart. Kea's queue size, worker count and per-packet logging are
  unchanged.

### Migrations

- `b7d2e4f91a08` — #2889, adds the nullable
  `dhcp_metric_sample.queue_evicted`.
