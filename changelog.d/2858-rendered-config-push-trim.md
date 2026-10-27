### Fixed

- **The DNS agent's rendered-config push fits the control plane's limits
  (#2858).** Since the 8 MiB request cap, a group whose rendered files
  passed 8 MiB had its push refused with 413, so the console's
  rendered-config view stopped updating. The agent now cuts each file to
  256 KB and keeps the measured JSON body under the cap, preferring
  `named.conf` and other config over zone files. A cut file ends in a
  visible marker, and files left out are listed in
  `_omitted_by_agent.txt`.
