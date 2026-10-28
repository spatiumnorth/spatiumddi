### Fixed

- **Requests Kea evicts from its full packet queue are now counted
  (#2889).** In a burst deeper than kea-dhcp4's 1,024-packet
  multi-threading queue, Kea drops the oldest queued requests and keeps
  no statistic for it, so `socket_drop`, `receive_drop` and
  `pkt4-received` all stayed silent while clients waited out retransmit
  rounds. The DHCP agent now counts DHCPv4 arrivals at Kea's intake with
  a BPF-filtered `AF_PACKET` socket of its own (the `CAP_NET_RAW` it
  already holds, no new privilege) and reports `queue_evicted` =
  arrivals − DHCPv4 `socket_drop` − `pkt4-received` per bucket. The
  filter counts only packets to the addresses Kea serves from, and the
  arrivals are read on both sides of Kea's counter snapshot, so the
  skew between the reads can never be counted as eviction. The first read
  is aged (`packet-queue-size` ÷ 100 s, 10 s as rendered) before Kea is
  asked, so a request still waiting in a queue below its depth is never
  counted as evicted, however long the backlog lasts. The price is that
  under continuous background traffic the count can read low (never
  high) until a quieter read. An eviction is reported once the next
  sample confirms it, one bucket late. The Stats tab's DROPPED line and chip, the
  InfluxDB export, `find_dhcp_server_stats`'s `packet_loss` block and
  the default-on `dhcp_packets_dropped` alert include it. NULL means
  unmeasured: no raw socket, a DHCPv6-only server, or the bucket in
  which the counting socket reopened because Kea's interfaces or their
  addresses changed. The minute in which the agent starts or Kea
  restarts has no bucket at all, as for every counter since #980. The
  filter runs on every inbound IPv4 packet the host receives, not only
  DHCP. Kea's queue size, worker count and per-packet logging are
  unchanged.

### Migrations

- `b7d2e4f91a08` — #2889, adds the nullable
  `dhcp_metric_sample.queue_evicted`.
