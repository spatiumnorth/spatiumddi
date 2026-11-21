### Fixed

- Fleet: the appliance details' Delete is now disabled, with the same "Demote this node from the control-plane cluster first" reason as the table's Revoke, on a control-plane node, instead of opening a revoke dialog the server refuses with 409 (#4613).
