### Fixed

- The four unused `gss_tsig_*` columns (`gss_tsig_enabled`, `gss_tsig_keytab_path`, `gss_tsig_realm`, `gss_tsig_principal`) are dropped from `dns_server_options`, finishing the removal begun in the release that took them out of the API. They were never rendered into `named.conf`, so no DNS behaviour changes. A selective restore of a backup taken before this release still loads (#3592).
