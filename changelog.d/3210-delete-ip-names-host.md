### Fixed

- The Delete IP Address dialog now names the host beside the address ("192.168.0.22 (printer-3.corp.example.com)") and lists the DNS records that go with it by name and type (the A or AAAA record, its PTR, its aliases, and a count of any additional zones it is published in), in both the Mark as Orphan and Delete Permanently options. The Permanently Delete confirmation for an orphan and the bulk delete dialog name the addresses too. If the aliases cannot be read the dialog says so and still works (#3210).
