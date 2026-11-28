### Fixed

- `docs/features/IPAM.md` no longer says a non-empty subnet's delete is refused: the default delete moves it to the Trash and never refuses; only the permanent delete (super-admin) is refused with `409` until `force=true`, as `docs/TROUBLESHOOTING.md` already said. (#5029)
