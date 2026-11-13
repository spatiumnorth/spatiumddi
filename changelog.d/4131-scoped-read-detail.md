### Fixed

- A failed self-service request now shows its requester a reason that names nothing they cannot read (another DHCP scope, a template, a DNS record's id or CNAME target, a DHCP pool's bounds); the approver and the audit log keep the full reason. A template of the wrong kind is answered like an unknown template id at submit.
