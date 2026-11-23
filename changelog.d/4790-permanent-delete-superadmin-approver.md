### Fixed

- A queued permanent delete (subnet, block, space, DNS zone, DHCP scope, DHCP server group) approved by a Change Approver who is not a superadmin no longer ends the request `failed` with "Superadmin required". The refusal now leaves it pending for a superadmin approver with the reason spelled out, and the queue no longer offers Approve to an approver who is not a superadmin on those rows.
