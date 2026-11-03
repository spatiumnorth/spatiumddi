### Fixed

- Six more edit dialogs (DNS Edit Server, TSIG key Edit metadata, DNS Pool, the zone Dynamic updates ACL, DHCP Phone Profile and DHCP Device policy) read the object fresh when they open and save only the fields you changed, so a change made elsewhere since the list loaded is no longer undone by an unrelated edit. Pool members, ACL entries and phone-profile scopes added elsewhere are kept, and a Save with nothing changed sends nothing and closes (#3379).
