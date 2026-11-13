### Fixed

- A refused save in New Group, New Option Template, New Client Class, the IPAM Create / Edit block and subnet dialogs, and Edit Blocked Domain / Edit Exception is now announced to a screen reader: a shared `FormError` draws the reason as `role="alert"` (#3821). The remaining dialogs still draw a plain red line and move over as they are touched.
