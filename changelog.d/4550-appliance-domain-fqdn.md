### Added

- Appliance: the installer (and a headless preseed) takes an optional DNS domain and DNS search domains. The FQDN goes into `/etc/hosts` so `hostname -f` returns it, the search list into the NetworkManager keyfile, and the FQDN into the self-signed Web UI certificate's SANs (#4550). Changing them after install from the UI/API and an outbound proxy setting are not part of this change.
