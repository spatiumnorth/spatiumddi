### Fixed

- **Edit Subnet stores a cleared VXLAN ID, Network role or VLAN (#2474).** `PUT /ipam/subnets/{id}` dropped an explicit null for `vxlan_id`, `subnet_role` and `vlan_ref_id`, so a clear closed the dialog and kept the old value. All three now clear, and clearing the VLAN reference also clears the VLAN tag derived from it (a `vlan_id` sent in the same request is kept, and a hand-typed tag on a subnet with no VLAN reference is left alone).
