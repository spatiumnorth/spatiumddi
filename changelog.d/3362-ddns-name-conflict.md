### Security

- **A DHCP client can no longer publish a name another record holds
  (#3362).** On a DDNS-enabled subnet, a laptop that called itself
  `www` got `www A <its lease IP>` added beside the operator's real
  `www A 203.0.113.10`, so about half the lookups for the web server
  went to the laptop. The same happened against a static IPAM host or
  another lease at the name. DDNS now publishes a name only when
  nobody else holds it or the address already owns it (RFC 4703): on a
  clash the lease is published as `dhcp-<ip>` instead, the other
  record is left alone, and a `ddns_name_conflict` warning and audit
  row name the subnet, IP, MAC, requested name and the holder. The
  warning and audit row are raised once per address and name, not on
  every renewal. The lease keeps the client's own hostname; the IPAM
  row shows the name that was published.
