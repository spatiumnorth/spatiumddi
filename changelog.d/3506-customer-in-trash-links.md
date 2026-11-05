### Fixed

- A customer moved to the Trash is now named as such wherever something still points at it: the multicast group, circuit and shared customer pickers keep it selected as "(customer in Trash)" instead of showing None, and the lists' customer chips (and the multicast list's Customer cell) say "(customer in Trash)" instead of going blank or showing an id fragment. A user who may read only some customers, or whose customer list could not be read, is never told a customer they cannot see is in the Trash (#3506).
