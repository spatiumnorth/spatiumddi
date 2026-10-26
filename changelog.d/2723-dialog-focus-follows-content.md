### Fixed

- **A dialog keeps keyboard focus when its content changes (#2723).** After Continue in a two-step delete (DNS and IPAM), focus fell to the page body while step 2 was open; it now moves onto the dialog. A dialog that replaces a loading dialog (DHCP Delete Server Group) now returns focus to the button that opened the first one when it closes.
