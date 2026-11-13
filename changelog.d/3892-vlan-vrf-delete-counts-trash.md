### Fixed
- Deleting a VLAN, a router or a VRF now counts the subnets, IP spaces and IP blocks sitting in the Trash that still carry it. The delete is refused (a VRF needs force-detach) instead of silently clearing their link, which a restore does not bring back, and the dialogs say so (#3892).
