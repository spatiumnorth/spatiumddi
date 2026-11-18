### Fixed

- A BIND9 agent's start-up zone-state report now keeps each zone's type and the group's views, so transferred secondary zones no longer read as drift ("1/1 drift · target 0") after every agent start. (#4053)
