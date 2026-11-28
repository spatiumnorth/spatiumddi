### Added

- BIND9 secondary and stub zones can now name a TSIG key and a TLS hostname per primary (`master_options`, rendered `primaries { ip port 853 key "k" tls … }`), so SpatiumDDI can be a secondary of a primary that requires TSIG (a Windows DC, an Infoblox grid) or serves zone transfers over TLS (XoT). A group option, `allow_transfer_tls_only`, renders `allow-transfer transport tls` to serve transfers over TLS through the DoT listener. Both are default-off, BIND9 only, optional on the wire so older agents keep rendering plain transfers, and exposed in the zone and group-options dialogs and the Copilot's zone and encrypted-transport reads. (#3568)

### Migrations

- `d3568a7f1c42` — #3568, adds `dns_zone.master_options` and `dns_server_options.allow_transfer_tls_only`.
