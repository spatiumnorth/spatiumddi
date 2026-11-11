### Fixed

- Deleting a VLAN, a router with a bound VLAN, a subnet from the Trash (by hand, by the nightly purge or through the copilot), an address for good, or a network device with a bound switch port no longer silently deletes the E911 location binding keyed to it. As with a site, the delete is refused with a 409 naming the binding, the nightly purge keeps such a subnet in the Trash, and the delete dialogs say so. Remove the binding under Network > E911 > Bindings first.
