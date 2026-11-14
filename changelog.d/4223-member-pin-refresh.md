### Fixed

- Appliance cluster members keep their control-plane certificate pin current: the CA-signed pin list now carries the vouched certificates' PEM, and a member on the node-local http path re-reads it every few minutes and replaces a stale pin (`supervisor.tls.pin_refreshed`). A pin left over from before cluster formation no longer makes the first https fallback after an upgrade fail verification and repin.
