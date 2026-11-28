### Fixed

- A user whose role is scoped to one subnet and one DNS zone can now pick that zone in Allocate IP, bulk allocate and the address editor. The zone picker used to read the group's full zone list, which that role is refused, so it offered no zone; it now falls back to the zones the user may write (#4854).
