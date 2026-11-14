### Fixed

- Paginated lists no longer skip or repeat rows between pages while the data is changing: the shared `paginate` helper now ends every ordering in the primary key, and the lease history, audit log, new-device, network ARP / FDB / neighbour, packet-capture, nmap and IP-address search lists do the same, so rows sharing a sort value (DHCP leases with the same `last_seen_at`) have a stable order across page requests (#4149).
