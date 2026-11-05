### Fixed

- The four `gss_tsig_*` DNS server options (`gss_tsig_enabled`, `gss_tsig_keytab_path`, `gss_tsig_realm`, `gss_tsig_principal`) are removed from the API. They were stored and returned but never rendered into `named.conf`, so setting them did nothing; a client that still sends them has them ignored. The DNS docs no longer prescribe the obsolete `tkey-domain`, and now say GSS-TSIG / "Secure only" AD zones are not supported yet (#1128, #444).
