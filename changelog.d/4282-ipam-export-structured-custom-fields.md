### Fixed
- The IPAM XLSX export no longer answers 500 when a subnet or address custom field holds a list or object, and the CSV export no longer writes a Python repr: both write such values as compact JSON text, and importing that file reads a `multi_select` field's JSON text back into a list (text fields stay text).
