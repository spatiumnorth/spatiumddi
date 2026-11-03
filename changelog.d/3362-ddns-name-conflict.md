### Security

- **A DHCP client can no longer publish a name another record holds
  (#3362).** On a DDNS-enabled subnet, a laptop that called itself
  `www` got `www A <its lease IP>` added beside the operator's real
  `www A 203.0.113.10`, so about half the lookups for the web server
  went to the laptop. The same happened against a static IPAM host or
  another lease at the name. DDNS now publishes a name only when
  nothing else is at it or the address already owns it (RFC 4703).
  Any record counts, so an MX- or TXT-only name, a CNAME or an NS
  delegation is not taken over either, and another address's
  generated `dhcp-<ip>` name is never available to a client. On a
  clash the lease is published as its own `dhcp-<ip>` instead and the
  other record is left alone; if that name is taken too, nothing is
  published and the IPAM row is left without a name, so Sync DNS
  cannot publish the client's name later. A `ddns_name_conflict`
  warning and audit row name the subnet, IP, MAC, requested name and
  the holder, at most once per address every five minutes. The lease
  keeps the client's own hostname; the IPAM row shows the name that
  was published.
