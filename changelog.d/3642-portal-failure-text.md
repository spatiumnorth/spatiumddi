### Fixed

- A request-portal request that fails when an approver applies it now words its reason from the requester's own reads: collision messages no longer name the address, subnet or DHCP pool bounds they found, and a target the requester cannot read is reported as not found. A non-HTTP error at apply (database errors above all) is shown as a plain "internal error" sentence instead of raw driver text, and the request arguments for a new subnet, DNS record, DHCP reservation and IP address now carry length limits matching their database columns, so an over-long value is refused at submit.
