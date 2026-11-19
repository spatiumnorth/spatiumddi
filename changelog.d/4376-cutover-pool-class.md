### Fixed

- The Windows DHCP cutover now refuses to activate a managed scope that has a pool restricted to a client class that no longer renders (for example a disabled phone profile), the same check the scope's own activation applies. It is reported as a blocker in readiness and re-checked before the Windows scope is deactivated, so the subnet is never left without a working DHCP scope (#4376).
