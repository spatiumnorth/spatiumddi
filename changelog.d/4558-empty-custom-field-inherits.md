### Fixed

- A custom field cleared in Edit Subnet or Edit IP Block no longer saves an empty value that hides the parent block's value: the effective fields of a subnet and of a block now read an empty custom field value as "none of its own", and the dialogs send no key for a cleared field. (#4558)
