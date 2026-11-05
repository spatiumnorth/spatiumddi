### Fixed

- Setting DNSSEC validation to `yes` on a BIND9 group with no trust anchor is now refused with a 422 (BIND 9.20 will not load that config and the group stopped converging). The same applies to removing the group's last trust anchor under `yes`, adding a BIND9 server to such a group, and to a `yes` platform default for new groups; the message offers `auto` (built-in root key) or adding an anchor. A row already in that state is rendered as `auto` so the group keeps converging, and the options page says so.
