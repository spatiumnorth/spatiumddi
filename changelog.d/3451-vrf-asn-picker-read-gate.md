### Fixed

- New and Edit IP Space / IP Block no longer offer a VRF or Origin ASN picker holding only "None" to a user who cannot read VRFs or ASNs: the picker is disabled with the reason, and an existing link shows as "Linked (not visible to your role)" instead of "None", and the space dialogs no longer link the VRFs page to that user. Saving leaves the link untouched ([#3451](https://github.com/spatiumnorth/spatiumddi/issues/3451)).
