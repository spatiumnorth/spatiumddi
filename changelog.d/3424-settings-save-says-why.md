### Fixed

- **The LLDP, NTP, DNS resolver, Syslog and SNMP settings say why a
  save was refused (#3424).** A save the server refused showed only
  "Failed to save: Request failed with status code 422" (or 403), so
  an operator who typed one bad value was not told which one. Each
  section now shows the server's reason, for example "Failed to save:
  ntp_allow_client_networks: invalid CIDR: '10.0.0.0/33' (...)", or
  the demo-mode refusal's sentence, as the APT and SSH settings
  already did.
