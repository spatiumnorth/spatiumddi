### Fixed

- Attaching a blocklist to a BIND9 server group no longer turns DNSSEC validation off for the whole group. The group keeps the `dnssec-validation` setting shown in Settings: blocked names are still rewritten for every client (DO bit set or not), and every other signed name is validated again, so a forged answer is refused with SERVFAIL instead of accepted (#3563).
