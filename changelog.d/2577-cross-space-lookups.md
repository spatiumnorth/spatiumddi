### Fixed

- **Lookups that matched an address or MAC in any IP space now stay in their
  own space (#2577).** IP spaces are independent networks, so the same
  address or MAC in two of them is not the same thing.
  - **nmap → Stamp into IPAM** wrote each host into whichever space's subnet
    the database returned first. It now uses the space you pick in the dialog,
    or the space of the IPAM row the scan was launched from — the dialog's
    "Automatic" option names that space, also when the scan is opened from
    History (the scan list now carries the space), and the result says which
    space was stamped. Without either, a host whose address is in more than one space
    is skipped and listed as ambiguous.
  - **DHCP fingerprint profiling** stamped the device type onto every row
    with that MAC, in every space. It now stamps only the spaces the
    reporting DHCP server's scopes serve; a server in no server group falls
    back to stamping only when every row with that MAC is in one space.
  - **The MAC collision warning** on create, edit and next-IP fired for a MAC
    used in another space. It now checks the same space only.
  - **New-device detection** treated a MAC allocated in one space as known
    everywhere, hiding a first sighting in another space. The known fleet is
    now per space. The MAC allowlist stays platform-wide.
  - **NAT mappings** linked an internal or external IP to an arbitrary row
    when the address existed in several spaces. They now leave it unlinked,
    or use the internal subnet's space when one is set.
  - The Copilot's **find_switchport** reports the candidates when an IP is in
    several spaces with different MACs and takes a `space_id`; **find_ip**
    labels each match with its space.
