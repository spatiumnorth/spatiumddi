### Fixed

- The IPAM tree now honours Settings → IPAM "Default Expanded Depth": blocks nested deeper than the stored depth start collapsed instead of every level opening. A block deeper than that still opens when the selected subnet or block is inside it, so a selection is never hidden.
