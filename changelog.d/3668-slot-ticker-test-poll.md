### Fixed

- An appliance runner test sampled the in-flight stamp a fixed 1.3 s apart and could flake on a loaded runner; it now polls for the stamp to advance (#3668).
