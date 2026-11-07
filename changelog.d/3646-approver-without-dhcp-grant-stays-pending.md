### Fixed

- Approving a static DHCP address request as an approver who may not write DHCP reservations now answers 403 with the reason and leaves the request pending for an approver who holds the grant, instead of ending it `failed` for good (#3646).
