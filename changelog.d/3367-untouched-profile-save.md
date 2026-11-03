### Fixed

- An untouched Save of a DHCP PXE profile no longer deletes and re-creates its boot rules under new ids, audits `matches` as changed, or changes the rendered Kea config (the class names embed the rule id, so it used to push a config to every agent). Unchanged rules keep their ids, changed ones are updated in place, and only a real addition or removal creates or deletes a rule. An untouched Save of a phone profile no longer writes a second audit row naming `scope_attachments`; the scope list is only rewritten when it actually changed.
